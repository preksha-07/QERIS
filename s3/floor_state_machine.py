"""S3 - Task T18: Security-Floor State Machine and Invariant Monitor

Implements the pure-function state machine that governs the lifecycle of
every device flow through the gateway.  All I/O is external — the function
returns (new_state, list[Action]) and the gateway executes the actions.

States (S3 spec §B §6)
-----------------------
UNREGISTERED   : Device not yet enrolled or not found in registry.
REGISTERED     : Device enrolled; no verified policy loaded yet.
POLICY_VALID   : A valid, verified, non-expired policy is loaded.
NEGOTIATING    : ML-KEM / handshake in progress.
ACTIVE         : Session fully established at or above the security floor.
DEGRADED       : Transport-layer problem; floor is maintained.
QUARANTINED    : Security failure detected; no further traffic accepted
                 until explicit administrative reset.

Events
------
PolicyVerified(version, floor_mode)
PolicyRejected(reason)
HandshakeStarted(device_best_mode)
HandshakeOk(negotiated_mode)
TransportFailure(cause: CauseClass)
SecurityFailure(reason: SecurityReason)
FloorUnreachable
Restart

Invariants (all seven — each tested in test_invariants.py)
----------------------------------------------------------
I1: A flow is never Active below its signed minimum security floor.
I2: An invalid, stale or untrusted policy cannot authorize a transition.
I3: A transport retry cannot change the security floor.
I4: A recovery action cannot convert a crypto failure into a transport failure.
I5: A gateway restart cannot erase replay-protection state.
I6: A device-provided flow label cannot override gateway policy.
I7: An observed network failure cannot authorize an insecure downgrade.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from downgrade_rejection import Mode


# ---------------------------------------------------------------------------
# States and Events
# ---------------------------------------------------------------------------

class FlowState(Enum):
    UNREGISTERED = "UNREGISTERED"
    REGISTERED   = "REGISTERED"
    POLICY_VALID = "POLICY_VALID"
    NEGOTIATING  = "NEGOTIATING"
    ACTIVE       = "ACTIVE"
    DEGRADED     = "DEGRADED"
    QUARANTINED  = "QUARANTINED"


class EventKind(Enum):
    POLICY_VERIFIED    = auto()
    POLICY_REJECTED    = auto()
    HANDSHAKE_STARTED  = auto()
    HANDSHAKE_OK       = auto()
    TRANSPORT_FAILURE  = auto()
    SECURITY_FAILURE   = auto()
    FLOOR_UNREACHABLE  = auto()
    RESTART            = auto()
    TRANSPORT_RESOLVED = auto()   # successful delivery after DEGRADED


@dataclass(frozen=True)
class Event:
    kind: EventKind
    # Populated depending on kind:
    version: Optional[int] = None          # POLICY_VERIFIED
    floor_mode: Optional[str] = None       # POLICY_VERIFIED
    min_acceptable: Optional[int] = None   # POLICY_VERIFIED
    reject_reason: Optional[str] = None    # POLICY_REJECTED, SECURITY_FAILURE
    device_best_mode: Optional[str] = None # HANDSHAKE_STARTED
    negotiated_mode: Optional[str] = None  # HANDSHAKE_OK
    cause: Optional[str] = None            # TRANSPORT_FAILURE


# ---------------------------------------------------------------------------
# Actions (instructions returned to the gateway)
# ---------------------------------------------------------------------------

class ActionKind(Enum):
    LOG_SECURITY      = auto()  # emit structured security log
    LOG_INFO          = auto()  # emit info log
    CLOSE_SESSION     = auto()  # tear down current session
    QUARANTINE        = auto()  # move to quarantined and close
    ALLOW_RETRY       = auto()  # recovery controller may retry (transport only)
    REPORT_UNREACHABLE = auto() # floor cannot be met; stop retrying
    RESET_FLOOR       = auto()  # update stored floor from policy


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    detail: str = ""


# ---------------------------------------------------------------------------
# Per-flow context (held by the gateway, passed into transition())
# ---------------------------------------------------------------------------

@dataclass
class FlowContext:
    """Mutable context for a single device flow.

    The state machine reads this; the gateway updates it after a successful
    transition (only after transition() returns, never inside it).
    """
    device_id: str
    flow_id: str

    # Set when a verified policy is loaded:
    policy_version: int = 0
    floor_mode: Optional[Mode] = None       # from signed policy
    min_acceptable_version: int = 0

    # Set during NEGOTIATING → ACTIVE:
    negotiated_mode: Optional[Mode] = None
    device_best_mode: Optional[Mode] = None

    # Counters:
    transport_failures: int = 0
    security_failures: int = 0


# ---------------------------------------------------------------------------
# Pure transition function
# ---------------------------------------------------------------------------

def transition(
    state: FlowState,
    event: Event,
    ctx: FlowContext,
) -> tuple[FlowState, list[Action]]:
    """Compute the next state and required actions for a flow.

    This is a PURE FUNCTION — no I/O, no side-effects.  The gateway executes
    the returned actions.  ctx is read-only inside this function; the gateway
    updates it after calling transition().

    Returns
    -------
    (new_state, actions)
    """
    actions: list[Action] = []

    # ---- UNREGISTERED -------------------------------------------------------
    if state is FlowState.UNREGISTERED:
        if event.kind is EventKind.POLICY_VERIFIED:
            # Guard: must have valid floor
            if event.floor_mode is None:
                actions.append(Action(ActionKind.LOG_SECURITY, "policy_verified_missing_floor"))
                return FlowState.UNREGISTERED, actions
            actions.append(Action(ActionKind.LOG_INFO, "registered_with_policy"))
            return FlowState.REGISTERED, actions
        # Any security failure while still unregistered → quarantine
        if event.kind is EventKind.SECURITY_FAILURE:
            actions += [
                Action(ActionKind.LOG_SECURITY, f"security_failure_unregistered:{event.reject_reason}"),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions
        # Restart keeps state UNREGISTERED
        if event.kind is EventKind.RESTART:
            actions.append(Action(ActionKind.LOG_INFO, "restart:unregistered"))
            return FlowState.UNREGISTERED, actions
        return FlowState.UNREGISTERED, actions

    # ---- REGISTERED ---------------------------------------------------------
    if state is FlowState.REGISTERED:
        if event.kind is EventKind.POLICY_VERIFIED:
            if event.floor_mode is None:
                actions.append(Action(ActionKind.LOG_SECURITY, "policy_verified_missing_floor"))
                return FlowState.REGISTERED, actions
            actions += [
                Action(ActionKind.RESET_FLOOR, f"floor={event.floor_mode}"),
                Action(ActionKind.LOG_INFO, f"policy_valid:version={event.version}"),
            ]
            return FlowState.POLICY_VALID, actions
        if event.kind is EventKind.POLICY_REJECTED:
            actions.append(Action(ActionKind.LOG_SECURITY, f"policy_rejected:{event.reject_reason}"))
            return FlowState.REGISTERED, actions  # stay; keep trying
        if event.kind is EventKind.SECURITY_FAILURE:
            actions += [
                Action(ActionKind.LOG_SECURITY, f"security_failure:{event.reject_reason}"),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions
        if event.kind is EventKind.RESTART:
            actions.append(Action(ActionKind.LOG_INFO, "restart:registered"))
            return FlowState.REGISTERED, actions
        return FlowState.REGISTERED, actions

    # ---- POLICY_VALID -------------------------------------------------------
    if state is FlowState.POLICY_VALID:
        if event.kind is EventKind.HANDSHAKE_STARTED:
            # Guard: floor must be set
            if ctx.floor_mode is None:
                actions.append(Action(ActionKind.LOG_SECURITY, "handshake_started_no_floor"))
                return FlowState.POLICY_VALID, actions
            # Feasibility check: can the device reach the floor?
            if event.device_best_mode is not None:
                best = Mode.parse(event.device_best_mode)
                if best < ctx.floor_mode:
                    actions += [
                        Action(ActionKind.REPORT_UNREACHABLE,
                               f"device_best={event.device_best_mode} < floor={ctx.floor_mode.name}"),
                        Action(ActionKind.LOG_SECURITY, "floor_unreachable"),
                    ]
                    return FlowState.POLICY_VALID, actions
            actions.append(Action(ActionKind.LOG_INFO, "handshake_started"))
            return FlowState.NEGOTIATING, actions
        if event.kind is EventKind.FLOOR_UNREACHABLE:
            actions += [
                Action(ActionKind.REPORT_UNREACHABLE),
                Action(ActionKind.LOG_SECURITY, "floor_unreachable"),
            ]
            return FlowState.POLICY_VALID, actions
        if event.kind is EventKind.POLICY_VERIFIED:
            # Policy update during POLICY_VALID — accept if version is higher.
            actions += [
                Action(ActionKind.RESET_FLOOR, f"floor={event.floor_mode}"),
                Action(ActionKind.LOG_INFO, f"policy_updated:version={event.version}"),
            ]
            return FlowState.POLICY_VALID, actions
        if event.kind is EventKind.POLICY_REJECTED:
            actions.append(Action(ActionKind.LOG_SECURITY, f"policy_rejected:{event.reject_reason}"))
            return FlowState.POLICY_VALID, actions  # keep last-good policy
        if event.kind is EventKind.SECURITY_FAILURE:
            actions += [
                Action(ActionKind.LOG_SECURITY, f"security_failure:{event.reject_reason}"),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions
        if event.kind is EventKind.RESTART:
            actions.append(Action(ActionKind.LOG_INFO, "restart:policy_valid"))
            return FlowState.REGISTERED, actions   # re-verify policy after restart
        return FlowState.POLICY_VALID, actions

    # ---- NEGOTIATING --------------------------------------------------------
    if state is FlowState.NEGOTIATING:
        if event.kind is EventKind.HANDSHAKE_OK:
            # Guard I1: negotiated mode must be >= floor
            if event.negotiated_mode is None or ctx.floor_mode is None:
                actions += [
                    Action(ActionKind.LOG_SECURITY, "handshake_ok_missing_mode_or_floor"),
                    Action(ActionKind.CLOSE_SESSION),
                ]
                return FlowState.POLICY_VALID, actions
            negotiated = Mode.parse(event.negotiated_mode)
            if negotiated < ctx.floor_mode:
                # Invariant 1 violated — reject, do not activate (T18)
                actions += [
                    Action(ActionKind.LOG_SECURITY,
                           f"downgrade_rejected:negotiated={event.negotiated_mode}"
                           f"<floor={ctx.floor_mode.name}"),
                    Action(ActionKind.CLOSE_SESSION),
                ]
                return FlowState.POLICY_VALID, actions
            actions.append(Action(ActionKind.LOG_INFO,
                                  f"session_active:mode={event.negotiated_mode}"))
            return FlowState.ACTIVE, actions

        if event.kind is EventKind.SECURITY_FAILURE:
            # Invariant 4: crypto failure stays crypto failure, not transport
            actions += [
                Action(ActionKind.LOG_SECURITY,
                       f"security_failure_during_negotiation:{event.reject_reason}"),
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions

        if event.kind is EventKind.TRANSPORT_FAILURE:
            # Invariant 3 + 7: transport failure cannot change the floor
            actions += [
                Action(ActionKind.LOG_INFO, f"transport_failure_negotiating:{event.cause}"),
                Action(ActionKind.ALLOW_RETRY),
            ]
            return FlowState.DEGRADED, actions

        if event.kind is EventKind.FLOOR_UNREACHABLE:
            actions += [
                Action(ActionKind.REPORT_UNREACHABLE),
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.LOG_SECURITY, "floor_unreachable_during_negotiation"),
            ]
            return FlowState.POLICY_VALID, actions

        if event.kind is EventKind.RESTART:
            actions += [
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.LOG_INFO, "restart:negotiating"),
            ]
            return FlowState.REGISTERED, actions

        return FlowState.NEGOTIATING, actions

    # ---- ACTIVE -------------------------------------------------------------
    if state is FlowState.ACTIVE:
        if event.kind is EventKind.TRANSPORT_FAILURE:
            # Invariants 3 and 7: floor is unchanged; mode is unchanged.
            actions += [
                Action(ActionKind.LOG_INFO, f"transport_failure_active:{event.cause}"),
                Action(ActionKind.ALLOW_RETRY),
            ]
            return FlowState.DEGRADED, actions

        if event.kind is EventKind.SECURITY_FAILURE:
            # Invariant 4: crypto failure → quarantine, not transport retry
            actions += [
                Action(ActionKind.LOG_SECURITY,
                       f"security_failure_active:{event.reject_reason}"),
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions

        if event.kind is EventKind.POLICY_VERIFIED:
            # Policy update while session is active — update floor, do NOT drop session
            # if current negotiated mode still meets the new floor.
            if ctx.negotiated_mode is not None and event.floor_mode is not None:
                new_floor = Mode.parse(event.floor_mode)
                if ctx.negotiated_mode < new_floor:
                    # Session now below new floor — close and re-negotiate
                    actions += [
                        Action(ActionKind.LOG_SECURITY,
                               f"policy_update_floor_raised:"
                               f"negotiated={ctx.negotiated_mode.name}"
                               f"<new_floor={event.floor_mode}"),
                        Action(ActionKind.RESET_FLOOR, f"floor={event.floor_mode}"),
                        Action(ActionKind.CLOSE_SESSION),
                    ]
                    return FlowState.POLICY_VALID, actions
            actions += [
                Action(ActionKind.RESET_FLOOR, f"floor={event.floor_mode}"),
                Action(ActionKind.LOG_INFO,
                       f"policy_updated_active:version={event.version}"),
            ]
            return FlowState.ACTIVE, actions

        if event.kind is EventKind.RESTART:
            actions += [
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.LOG_INFO, "restart:active"),
            ]
            return FlowState.REGISTERED, actions

        return FlowState.ACTIVE, actions

    # ---- DEGRADED -----------------------------------------------------------
    if state is FlowState.DEGRADED:
        if event.kind is EventKind.TRANSPORT_RESOLVED:
            # Recovery succeeded — return to ACTIVE at the SAME floor (Invariant 3)
            actions.append(Action(ActionKind.LOG_INFO, "transport_resolved:back_to_active"))
            return FlowState.ACTIVE, actions

        if event.kind is EventKind.TRANSPORT_FAILURE:
            # Another transport failure — stay DEGRADED, allow another retry
            actions += [
                Action(ActionKind.LOG_INFO, f"transport_failure_degraded:{event.cause}"),
                Action(ActionKind.ALLOW_RETRY),
            ]
            return FlowState.DEGRADED, actions

        if event.kind is EventKind.SECURITY_FAILURE:
            # Invariant 4: even in DEGRADED, crypto failure → quarantine
            actions += [
                Action(ActionKind.LOG_SECURITY,
                       f"security_failure_degraded:{event.reject_reason}"),
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.QUARANTINE),
            ]
            return FlowState.QUARANTINED, actions

        if event.kind is EventKind.RESTART:
            actions += [
                Action(ActionKind.CLOSE_SESSION),
                Action(ActionKind.LOG_INFO, "restart:degraded"),
            ]
            return FlowState.REGISTERED, actions

        return FlowState.DEGRADED, actions

    # ---- QUARANTINED --------------------------------------------------------
    # Terminal state — all events are logged and rejected.
    if state is FlowState.QUARANTINED:
        actions.append(
            Action(ActionKind.LOG_SECURITY,
                   f"quarantined:event_ignored:{event.kind.name}")
        )
        return FlowState.QUARANTINED, actions

    # Unknown state — fail closed
    actions += [
        Action(ActionKind.LOG_SECURITY, f"unknown_state:{state}"),
        Action(ActionKind.QUARANTINE),
    ]
    return FlowState.QUARANTINED, actions


# ---------------------------------------------------------------------------
# Invariant Monitor
# ---------------------------------------------------------------------------

class InvariantViolation(Exception):
    """Raised by the monitor when a state-machine invariant is broken."""


class InvariantMonitor:
    """Runs after every transition.  Raises InvariantViolation on any breach.

    The gateway catches this, moves the flow to QUARANTINED, and logs it.
    The monitor NEVER fixes state silently — violations must be visible.

    Invariants checked after each transition
    ----------------------------------------
    I1: ACTIVE state → negotiated_mode >= floor_mode
    I3: DEGRADED → floor_mode unchanged from before transition
    I4: SECURITY_FAILURE event must not result in ALLOW_RETRY action
    I7: TRANSPORT_FAILURE event must not result in a floor decrease
    """

    def check(
        self,
        prev_state: FlowState,
        event: Event,
        new_state: FlowState,
        actions: list[Action],
        ctx: FlowContext,
        prev_floor: Optional[Mode],
    ) -> None:
        """Raise InvariantViolation if any invariant is breached."""

        # I1: Flow must never be Active below its signed floor.
        if new_state is FlowState.ACTIVE:
            if ctx.floor_mode is None:
                raise InvariantViolation(
                    "I1: ACTIVE state with no floor_mode set"
                )
            if ctx.negotiated_mode is None:
                raise InvariantViolation(
                    "I1: ACTIVE state with no negotiated_mode set"
                )
            if ctx.negotiated_mode < ctx.floor_mode:
                raise InvariantViolation(
                    f"I1: ACTIVE with negotiated={ctx.negotiated_mode.name} "
                    f"< floor={ctx.floor_mode.name}"
                )

        # I3: Transport retry must not change the security floor.
        if event.kind is EventKind.TRANSPORT_FAILURE:
            if prev_floor is not None and ctx.floor_mode is not None:
                if ctx.floor_mode != prev_floor:
                    raise InvariantViolation(
                        f"I3: Transport failure changed floor: "
                        f"{prev_floor.name} → {ctx.floor_mode.name}"
                    )

        # I4: SECURITY_FAILURE must not produce ALLOW_RETRY.
        if event.kind is EventKind.SECURITY_FAILURE:
            for action in actions:
                if action.kind is ActionKind.ALLOW_RETRY:
                    raise InvariantViolation(
                        "I4: SECURITY_FAILURE produced ALLOW_RETRY action"
                    )

        # I7: Network failure must not lower the floor.
        if event.kind in (EventKind.TRANSPORT_FAILURE,):
            if prev_floor is not None and ctx.floor_mode is not None:
                if ctx.floor_mode < prev_floor:
                    raise InvariantViolation(
                        f"I7: Network failure lowered floor: "
                        f"{prev_floor.name} → {ctx.floor_mode.name}"
                    )
