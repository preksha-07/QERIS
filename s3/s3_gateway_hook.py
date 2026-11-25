"""S3 - Integration Adapter: Gateway Hook  (S3 spec §J, Weeks 7-8)

Purpose
-------
This module is the single handoff point between:
    S2 gateway.py   →  S3 security/recovery logic  →  S2 response

S2 calls ``process_gateway_decision()`` after its own check_flow() and
optionally after receiving a PolicyVerificationResult from S1.

S3 then:
  1. Translates S2's string mode names (including "PQC") into Mode enums.
  2. Optionally bridges an S1 PolicyVerificationStatus into ObservedSignals.
  3. Runs the DowngradeRejector.
  4. Runs the FailureTaxonomy classifier if a failure signal is present.
  5. Feeds the classified event to the RecoveryController.
  6. Advances the FlowState via the pure transition() function.
  7. Logs the outcome via AuditLogger (S2+S4-compatible schema).
  8. Returns an S3HookResult that S2 can use to override/confirm its decision.

S2 Integration Contract
-----------------------
S2 passes a dict that mirrors the fields from its check_flow() response:

    {
        "device_id":      str,
        "flow_id":        str,
        "sensitivity":    str | None,
        "minimum_mode":   str | None,          # e.g. "HYBRID", "PQC"
        "requested_mode": str,                 # what the device asked for
        "policy_version": int | None,
        "decision":       str,                 # "ALLOW", "REJECT", "FLOOR_UNREACHABLE"
        "reason":         str,
    }

Optionally, S2 can pass:
    s1_status:      str | None   — PolicyVerificationStatus.name from S1
    device_best_mode: str | None — highest mode the device can do (from devices.json)

S3 returns S3HookResult which carries:
    final_decision:  "ALLOW" | "REJECT" | "FLOOR_UNREACHABLE"
    s3_verdict:      ControllerVerdict name  (for S4 logging)
    cause_label:     CauseClass value string (for S4 confusion matrix)
    detail:          human-readable explanation
    close_session:   bool
    backoff_ms:      int  (>0 only on RETRY)

Terminology alignment
---------------------
S2 uses "PQC" (SECURITY_LEVEL = {"CLASSICAL":1, "HYBRID":2, "PQC":3}).
S3 uses "PQ" internally.  Mode.parse() resolves both transparently.

S1's PolicyVerificationStatus names → ObservedSignals translation is done by
ObservedSignals.from_s1_status() defined in failure_taxonomy.py.

Authority checking
------------------
S2's policy.json uses ``"authority_id": "QERIS-GATEWAY"`` per flow.
The hook checks authority_id against TRUSTED_AUTHORITIES (configurable).
If authority_id is missing or not in the trusted set, unknown_authority=True
is set and the event is classified as SECURITY_FAILURE/UNKNOWN_AUTHORITY.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from audit_logger import AuditLogger, EventKind
from downgrade_rejection import DowngradeRejector, Mode
from failure_taxonomy import (
    CauseClass,
    ClassifiedEvent,
    FailureTaxonomy,
    ObservedSignals,
    SecurityReason,
)
from floor_state_machine import (
    Event,
    EventKind as FSMEventKind,
    FlowContext,
    FlowState,
    transition,
)
from recovery_controller import ControllerDecision, ControllerVerdict, RecoveryController


# ---------------------------------------------------------------------------
# Trusted authority registry
# ---------------------------------------------------------------------------

#: Set of authority_id values that S3 trusts.
#: Populated from S2's policy.json authority_id field value.
#: Extend this set if additional signing authorities are added.
TRUSTED_AUTHORITIES: frozenset[str] = frozenset({"QERIS-GATEWAY"})

# S2 decision strings
_DECISION_ALLOW           = "ALLOW"
_DECISION_REJECT          = "REJECT"
_DECISION_FLOOR_UNREACHABLE = "FLOOR_UNREACHABLE"


# ---------------------------------------------------------------------------
# Hook result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class S3HookResult:
    """Decision returned by S3 to S2 after security/recovery processing.

    Fields
    ------
    final_decision:
        "ALLOW" | "REJECT" | "FLOOR_UNREACHABLE"
        S3 may tighten S2's ALLOW to REJECT if a security signal is found.
        S3 never relaxes S2's REJECT to ALLOW.
    s3_verdict:
        ControllerVerdict.name — for S4 logging and ground-truth labelling.
    cause_label:
        CauseClass.value — for S4 confusion matrix (cause_label column).
    security_reason:
        SecurityReason.value or None — only set for SECURITY_FAILURE events.
    detail:
        Human-readable summary (not logged to the security log verbatim;
        only the structured fields go there).
    close_session:
        True if S2 must close the current session immediately.
    backoff_ms:
        Milliseconds to wait before retrying (only meaningful for RETRY).
    """
    final_decision: str
    s3_verdict: str
    cause_label: str
    security_reason: Optional[str]
    detail: str
    close_session: bool
    backoff_ms: int = 0


# ---------------------------------------------------------------------------
# Gateway hook (stateful — one instance per gateway process)
# ---------------------------------------------------------------------------

class S3GatewayHook:
    """Stateful integration adapter between S2 and S3.

    One instance should be created per gateway process (not per request).
    Session retry state is keyed by session_id (or device_id+flow_id pair).

    Parameters
    ----------
    audit_level:
        Passed through to AuditLogger.  "standard" is the recommended
        production setting; use "enhanced" for demo runs.
    rate_limit_per_min:
        AuditLogger rate limit.  0 = disabled (tests only).
    max_loss_retries:
        RecoveryController LOSS_TIMEOUT retry cap.
    max_mtu_retries:
        RecoveryController MTU_FRAGMENT retry cap.
    trusted_authorities:
        Override the default TRUSTED_AUTHORITIES frozenset.
    logger_sink:
        Custom sink for AuditLogger (file or StringIO).  Defaults to stdout.
    """

    def __init__(
        self,
        audit_level: str = "standard",
        rate_limit_per_min: int = 120,
        max_loss_retries: int = 3,
        max_mtu_retries: int = 2,
        trusted_authorities: frozenset[str] = TRUSTED_AUTHORITIES,
        logger_sink=None,
    ):
        self._taxonomy   = FailureTaxonomy()
        self._rejector   = DowngradeRejector()
        self._controller = RecoveryController(
            max_loss_retries=max_loss_retries,
            max_mtu_retries=max_mtu_retries,
        )
        self._logger = AuditLogger(
            audit_level=audit_level,
            rate_limit_per_min=rate_limit_per_min,
            sink=logger_sink,
        )
        self._trusted = trusted_authorities
        # Per-flow FSM state: keyed by (device_id, flow_id)
        self._flow_states: dict[tuple[str, str], FlowState] = {}
        self._flow_contexts: dict[tuple[str, str], FlowContext] = {}

    # ------------------------------------------------------------------ public

    def process_gateway_decision(
        self,
        gw_decision: dict[str, Any],
        *,
        session_id: Optional[str] = None,
        s1_status: Optional[str] = None,
        device_best_mode: Optional[str] = None,
    ) -> S3HookResult:
        """Main entry point called by S2 after check_flow().

        Parameters
        ----------
        gw_decision:
            Dict produced by S2's check_flow() endpoint response:
            {device_id, flow_id, sensitivity, minimum_mode, requested_mode,
             policy_version, decision, reason}
            May also contain ``authority_id``.
        session_id:
            Optional session identifier for retry-state keying.
            Defaults to ``"<device_id>:<flow_id>"`` if omitted.
        s1_status:
            Optional PolicyVerificationStatus.name from S1's verify_policy().
            If provided, translated to ObservedSignals via from_s1_status().
        device_best_mode:
            The highest mode the device can physically achieve (from S2's
            devices.json ``supported_modes``).  Used for floor-feasibility.
        """
        device_id      = gw_decision.get("device_id", "unknown")
        flow_id        = gw_decision.get("flow_id", "unknown")
        sensitivity    = gw_decision.get("sensitivity")
        minimum_mode   = gw_decision.get("minimum_mode")
        requested_mode = gw_decision.get("requested_mode", "CLASSICAL")
        policy_version = gw_decision.get("policy_version")
        s2_decision    = gw_decision.get("decision", _DECISION_REJECT)
        s2_reason      = gw_decision.get("reason", "")
        authority_id   = gw_decision.get("authority_id")

        sid = session_id or f"{device_id}:{flow_id}"
        flow_key = (device_id, flow_id)

        # Retrieve or initialise per-flow FSM context
        ctx = self._flow_contexts.setdefault(
            flow_key,
            FlowContext(device_id=device_id, flow_id=flow_id),
        )
        current_state = self._flow_states.get(flow_key, FlowState.REGISTERED)

        # ---- 1. Resolve Mode enums (accepts "PQC" via Mode.parse alias) ----
        try:
            floor_mode = Mode.parse(minimum_mode) if minimum_mode else None
        except ValueError:
            floor_mode = None

        try:
            neg_mode = Mode.parse(requested_mode) if requested_mode else None
        except ValueError:
            neg_mode = None

        try:
            dev_best = Mode.parse(device_best_mode) if device_best_mode else None
        except ValueError:
            dev_best = None

        ctx.floor_mode       = floor_mode
        ctx.negotiated_mode  = neg_mode
        ctx.device_best_mode = dev_best

        # ---- 2. Build ObservedSignals from all available evidence -----------
        signals = ObservedSignals()

        # 2a. Authority check (S2 passes authority_id per flow)
        if authority_id is not None and authority_id not in self._trusted:
            signals.unknown_authority = True

        # 2b. S1 verification status bridge
        if s1_status:
            s1_signals = ObservedSignals.from_s1_status(s1_status)
            # Merge: any True wins
            signals.auth_check_failed    = signals.auth_check_failed    or s1_signals.auth_check_failed
            signals.version_check_failed = signals.version_check_failed or s1_signals.version_check_failed
            signals.revoked_algorithm    = signals.revoked_algorithm    or s1_signals.revoked_algorithm
            signals.invalid_format       = signals.invalid_format       or s1_signals.invalid_format
            signals.unknown_authority    = signals.unknown_authority    or s1_signals.unknown_authority

        # 2c. S2 decision string → signals
        if s2_decision == _DECISION_FLOOR_UNREACHABLE:
            # S2 already determined the device cannot reach the floor
            ctx.device_best_mode = dev_best or floor_mode  # treat best == floor to confirm
            # No additional signal — handled as FLOOR_UNREACHABLE path below

        elif s2_decision == _DECISION_REJECT:
            reason_lc = s2_reason.lower()
            if "signature" in reason_lc or "policy" in reason_lc:
                signals.auth_check_failed = True
            elif "rollback" in reason_lc or "stale" in reason_lc or "version" in reason_lc:
                signals.version_check_failed = True
            elif "floor" in reason_lc or "mode" in reason_lc or "downgrade" in reason_lc:
                signals.mode_below_floor = True
            elif "unknown" in reason_lc and "flow" in reason_lc:
                signals.invalid_format = True
            else:
                # Generic reject with no specific signal → loss/timeout bucket
                signals.no_response = True

        # 2d. Downgrade check (only when S2 says ALLOW — verify independently)
        if s2_decision == _DECISION_ALLOW and floor_mode is not None and neg_mode is not None:
            dr = self._rejector.check(neg_mode, floor_mode)
            if dr.is_downgrade:
                signals.mode_below_floor = True

        # ---- 3. Classify the event -----------------------------------------
        has_any_signal = (
            signals.auth_check_failed
            or signals.version_check_failed
            or signals.version_jump_exceeded
            or signals.mode_below_floor
            or signals.unknown_authority
            or signals.revoked_algorithm
            or signals.invalid_format
            or signals.no_response
            or signals.fragment_size_exceeded
            or signals.fragment_count_exceeded
        )

        if has_any_signal:
            classified: ClassifiedEvent = self._taxonomy.classify(signals)
        else:
            # ALLOW with no failure signals — synthetic success event
            classified = ClassifiedEvent(
                cause=CauseClass.LOSS_TIMEOUT,   # placeholder (won't be used)
                signals=signals,
                label_confidence="high",
                notes="no_failure",
            )

        # ---- 4. FSM + Controller --------------------------------------------
        if s2_decision == _DECISION_FLOOR_UNREACHABLE:
            fsm_event = Event(kind=FSMEventKind.FLOOR_UNREACHABLE)
            new_state, _ = transition(current_state, fsm_event, ctx)
            self._flow_states[flow_key] = new_state

            result = S3HookResult(
                final_decision=_DECISION_FLOOR_UNREACHABLE,
                s3_verdict=ControllerVerdict.FLOOR_UNREACHABLE.name,
                cause_label=CauseClass.LOSS_TIMEOUT.value,
                security_reason=None,
                detail=f"floor_unreachable:device cannot reach {minimum_mode}",
                close_session=True,
            )

        elif classified.cause is CauseClass.SECURITY_FAILURE or (
            has_any_signal and classified.is_security()
        ):
            # Security failure — always terminal
            fsm_event = Event(
                kind=FSMEventKind.SECURITY_FAILURE,
                reject_reason=(
                    classified.security_reason.value
                    if classified.security_reason else "unknown"
                ),
            )
            new_state, _ = transition(current_state, fsm_event, ctx)
            self._flow_states[flow_key] = new_state

            controller_decision = ControllerDecision(
                verdict=ControllerVerdict.DISCARD_AND_LOG,
                cause=classified.cause,
                session_id=sid,
                attempt=1,
                close_session=True,
                detail=fsm_event.reject_reason or "security_failure",
            )
            result = S3HookResult(
                final_decision=_DECISION_REJECT,
                s3_verdict=controller_decision.verdict.name,
                cause_label=classified.cause.value,
                security_reason=(
                    classified.security_reason.value
                    if classified.security_reason else None
                ),
                detail=controller_decision.detail,
                close_session=True,
            )

        elif has_any_signal and not classified.is_security():
            # Transport failure — run recovery controller
            controller_decision = self._controller.handle(
                sid, classified, current_state, ctx
            )
            # Advance FSM
            if controller_decision.verdict == ControllerVerdict.FLOOR_UNREACHABLE:
                fsm_event = Event(kind=FSMEventKind.FLOOR_UNREACHABLE)
            elif controller_decision.is_terminal:
                fsm_event = Event(
                    kind=FSMEventKind.TRANSPORT_FAILURE,
                    cause=classified.cause,
                )
            else:
                fsm_event = Event(
                    kind=FSMEventKind.TRANSPORT_FAILURE,
                    cause=classified.cause,
                )
            new_state, _ = transition(current_state, fsm_event, ctx)
            self._flow_states[flow_key] = new_state

            if controller_decision.is_terminal:
                final = _DECISION_REJECT
            else:
                final = _DECISION_ALLOW   # retry approved

            result = S3HookResult(
                final_decision=final,
                s3_verdict=controller_decision.verdict.name,
                cause_label=classified.cause.value,
                security_reason=None,
                detail=controller_decision.detail,
                close_session=controller_decision.close_session,
                backoff_ms=controller_decision.backoff_ms,
            )

        else:
            # Clean ALLOW — no failures detected
            if floor_mode is not None:
                fsm_event = Event(
                    kind=FSMEventKind.POLICY_VERIFIED,
                    version=policy_version,
                    floor_mode=minimum_mode,
                    min_acceptable=1,
                )
                new_state, _ = transition(current_state, fsm_event, ctx)
                self._flow_states[flow_key] = new_state

            result = S3HookResult(
                final_decision=_DECISION_ALLOW,
                s3_verdict="NONE",
                cause_label="none",
                security_reason=None,
                detail="allow:all_checks_passed",
                close_session=False,
            )

        # ---- 5. Emit S2+S4 compatible audit log ----------------------------
        self._logger.log_gateway_decision(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=sensitivity,
            minimum_mode=minimum_mode,
            requested_mode=requested_mode,
            policy_version=policy_version,
            decision=result.final_decision,
            reason=result.detail,
            cause_label=result.cause_label if result.cause_label != "none" else None,
            s3_verdict=result.s3_verdict if result.s3_verdict != "NONE" else None,
        )

        return result

    def reset_session(self, session_id: str) -> None:
        """Clear retry counters after successful delivery.  Called by S2."""
        self._controller.reset(session_id)

    def close_session(self, session_id: str) -> None:
        """Remove retry state when a session is torn down.  Called by S2."""
        self._controller.close(session_id)

    def get_flow_state(self, device_id: str, flow_id: str) -> FlowState:
        """Return current FSM state for a flow (useful for S4 run scripts)."""
        return self._flow_states.get(
            (device_id, flow_id), FlowState.REGISTERED
        )

    def metrics_snapshot(self) -> dict[str, int]:
        """Delegate to AuditLogger counters (for S4 metrics collection)."""
        return self._logger.metrics_snapshot()
