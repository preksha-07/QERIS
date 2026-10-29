"""S3 - Task T20: Recovery Controller (floor-bounded, cause-specific)

Integrates the failure taxonomy, state machine, downgrade rejector, and
replay protection into a single decision point.

Design (S3 spec §D, threat model §6.6)
---------------------------------------
Before executing ANY recovery action the controller asks:
  "Does this action keep the negotiated mode at or above the floor?"
If not, the action is refused and FloorUnreachable is returned.

Per-cause action sets
---------------------
LOSS_TIMEOUT    : bounded retry with exponential backoff → FAIL at cap
MTU_FRAGMENT    : reduce fragment size, retry → FAIL at cap
COMPUTE         : extend timeout budget, retry → FAIL at cap (if class exists)
SECURITY_FAILURE: reject + log + quarantine. NEVER retry, NEVER weaken mode.

Floor-bounded guarantee (the research contribution)
----------------------------------------------------
Every action returned by this controller is pre-checked:
  allowed_action := action s.t. mode_after(action) >= floor
If no action in the allowed set keeps the mode at or above the floor,
the controller returns FloorUnreachable and ceases retrying.

This is the invariant the paper claims: recovery never activates a flow
below its floor across all injected failures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from downgrade_rejection import DowngradeRejector, Mode
from failure_taxonomy import CauseClass, ClassifiedEvent, FailureTaxonomy, ObservedSignals
from floor_state_machine import (
    Action, ActionKind, Event, EventKind, FlowContext, FlowState,
    InvariantMonitor, InvariantViolation, transition,
)


# ---------------------------------------------------------------------------
# Controller outcome
# ---------------------------------------------------------------------------

class ControllerVerdict(Enum):
    RETRY             = auto()   # safe to retry at same mode
    REFRAGMENT        = auto()   # reduce fragment size, retry
    EXTEND_TIMEOUT    = auto()   # give device more time (COMPUTE class)
    DISCARD_AND_LOG   = auto()   # security failure: terminal
    FLOOR_UNREACHABLE = auto()   # device cannot meet floor; stop retrying
    FAIL              = auto()   # retry cap reached; escalate


@dataclass(frozen=True)
class ControllerDecision:
    verdict: ControllerVerdict
    cause: CauseClass
    session_id: str
    attempt: int
    backoff_ms: int = 0
    close_session: bool = False
    detail: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.verdict in (
            ControllerVerdict.DISCARD_AND_LOG,
            ControllerVerdict.FLOOR_UNREACHABLE,
            ControllerVerdict.FAIL,
        )


# ---------------------------------------------------------------------------
# Per-session retry state
# ---------------------------------------------------------------------------

@dataclass
class _RetryState:
    loss_attempts: int = 0
    mtu_attempts: int = 0
    compute_attempts: int = 0
    last_backoff_ms: int = 0


# ---------------------------------------------------------------------------
# Recovery Controller
# ---------------------------------------------------------------------------

class RecoveryController:
    """Floor-bounded, cause-classified recovery controller.

    Parameters
    ----------
    max_loss_retries: int
        Retry cap for LOSS_TIMEOUT failures.
    max_mtu_retries: int
        Retry cap for MTU_FRAGMENT failures.
    max_compute_retries: int
        Retry cap for COMPUTE failures (ignored if COMPUTE class disabled).
    base_backoff_ms: int
        Initial backoff delay (LOSS_TIMEOUT).  Doubled each attempt.
    max_backoff_ms: int
        Cap on exponential backoff.
    compute_class_enabled: bool
        Set True only if COMPUTE failures were observed in pilot data.
    """

    def __init__(
        self,
        max_loss_retries: int = 3,
        max_mtu_retries: int = 2,
        max_compute_retries: int = 2,
        base_backoff_ms: int = 200,
        max_backoff_ms: int = 8000,
        compute_class_enabled: bool = False,
    ):
        self._max_loss = max_loss_retries
        self._max_mtu = max_mtu_retries
        self._max_compute = max_compute_retries
        self._base_ms = base_backoff_ms
        self._max_ms = max_backoff_ms
        self._compute_enabled = compute_class_enabled
        self._sessions: dict[str, _RetryState] = {}
        self._rejector = DowngradeRejector()
        self._monitor = InvariantMonitor()

    # ------------------------------------------------------------------ public

    def handle(
        self,
        session_id: str,
        classified_event: ClassifiedEvent,
        flow_state: FlowState,
        ctx: FlowContext,
    ) -> ControllerDecision:
        """Process a classified failure and return a floor-bounded verdict.

        Parameters
        ----------
        session_id: str
        classified_event: ClassifiedEvent  (from FailureTaxonomy.classify)
        flow_state: FlowState              (current state of the flow)
        ctx: FlowContext                   (current floor, mode, device caps)
        """
        state = self._sessions.setdefault(session_id, _RetryState())
        cause = classified_event.cause

        # ---- SECURITY_FAILURE is always terminal (Invariants 4, 7) ----------
        if cause is CauseClass.SECURITY_FAILURE:
            return ControllerDecision(
                verdict=ControllerVerdict.DISCARD_AND_LOG,
                cause=cause,
                session_id=session_id,
                attempt=1,
                close_session=True,
                detail=(
                    f"security_failure:terminal:"
                    f"{classified_event.security_reason.value if classified_event.security_reason else 'unknown'}"
                ),
            )

        # ---- Floor feasibility check (S3 spec §D) ---------------------------
        # If the device's best mode is below the policy floor, stop retrying.
        if ctx.floor_mode is not None and ctx.device_best_mode is not None:
            if not self._rejector.check_floor_reachable(
                ctx.floor_mode, ctx.device_best_mode
            ):
                return ControllerDecision(
                    verdict=ControllerVerdict.FLOOR_UNREACHABLE,
                    cause=cause,
                    session_id=session_id,
                    attempt=0,
                    close_session=True,
                    detail=(
                        f"floor_unreachable:"
                        f"device_best={ctx.device_best_mode.name},"
                        f"floor={ctx.floor_mode.name}"
                    ),
                )

        # ---- LOSS_TIMEOUT ---------------------------------------------------
        if cause is CauseClass.LOSS_TIMEOUT:
            return self._loss(session_id, state, ctx)

        # ---- MTU_FRAGMENT ---------------------------------------------------
        if cause is CauseClass.MTU_FRAGMENT:
            return self._mtu(session_id, state, ctx)

        # ---- COMPUTE (conditional) ------------------------------------------
        if cause is CauseClass.COMPUTE:
            if not self._compute_enabled:
                # Class disabled — treat as terminal to be conservative
                return ControllerDecision(
                    verdict=ControllerVerdict.DISCARD_AND_LOG,
                    cause=cause,
                    session_id=session_id,
                    attempt=1,
                    close_session=True,
                    detail="compute_class_disabled:treated_as_terminal",
                )
            return self._compute(session_id, state, ctx)

        # Unknown cause — fail closed (G6)
        return ControllerDecision(
            verdict=ControllerVerdict.DISCARD_AND_LOG,
            cause=cause,
            session_id=session_id,
            attempt=1,
            close_session=True,
            detail="unknown_cause:fail_closed",
        )

    def reset(self, session_id: str) -> None:
        """Clear retry counters after successful delivery."""
        self._sessions.pop(session_id, None)

    def close(self, session_id: str) -> None:
        """Remove all state when session is torn down."""
        self._sessions.pop(session_id, None)

    # ----------------------------------------------------------------- private

    def _backoff(self, attempt: int) -> int:
        return min(self._base_ms * (2 ** (attempt - 1)), self._max_ms)

    def _floor_ok(self, ctx: FlowContext) -> bool:
        """True if the current negotiated mode is still >= floor."""
        if ctx.floor_mode is None or ctx.negotiated_mode is None:
            return True  # no floor set yet — allow
        return ctx.negotiated_mode >= ctx.floor_mode

    def _loss(self, session_id: str, state: _RetryState, ctx: FlowContext) -> ControllerDecision:
        state.loss_attempts += 1
        attempt = state.loss_attempts
        if attempt > self._max_loss:
            return ControllerDecision(
                verdict=ControllerVerdict.FAIL,
                cause=CauseClass.LOSS_TIMEOUT,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail=f"loss:cap={self._max_loss}:giving_up",
            )
        # Invariant 3: retry must not change the floor
        if not self._floor_ok(ctx):
            return ControllerDecision(
                verdict=ControllerVerdict.FLOOR_UNREACHABLE,
                cause=CauseClass.LOSS_TIMEOUT,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail="loss_retry_would_breach_floor",
            )
        backoff = self._backoff(attempt)
        state.last_backoff_ms = backoff
        return ControllerDecision(
            verdict=ControllerVerdict.RETRY,
            cause=CauseClass.LOSS_TIMEOUT,
            session_id=session_id,
            attempt=attempt,
            backoff_ms=backoff,
            detail=f"loss:retry={attempt}/{self._max_loss}:backoff={backoff}ms",
        )

    def _mtu(self, session_id: str, state: _RetryState, ctx: FlowContext) -> ControllerDecision:
        state.mtu_attempts += 1
        attempt = state.mtu_attempts
        if attempt > self._max_mtu:
            return ControllerDecision(
                verdict=ControllerVerdict.FAIL,
                cause=CauseClass.MTU_FRAGMENT,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail=f"mtu:cap={self._max_mtu}:giving_up",
            )
        if not self._floor_ok(ctx):
            return ControllerDecision(
                verdict=ControllerVerdict.FLOOR_UNREACHABLE,
                cause=CauseClass.MTU_FRAGMENT,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail="mtu_refragment_would_breach_floor",
            )
        return ControllerDecision(
            verdict=ControllerVerdict.REFRAGMENT,
            cause=CauseClass.MTU_FRAGMENT,
            session_id=session_id,
            attempt=attempt,
            detail=f"mtu:refragment={attempt}/{self._max_mtu}",
        )

    def _compute(self, session_id: str, state: _RetryState, ctx: FlowContext) -> ControllerDecision:
        state.compute_attempts += 1
        attempt = state.compute_attempts
        if attempt > self._max_compute:
            return ControllerDecision(
                verdict=ControllerVerdict.FAIL,
                cause=CauseClass.COMPUTE,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail=f"compute:cap={self._max_compute}:giving_up",
            )
        if not self._floor_ok(ctx):
            return ControllerDecision(
                verdict=ControllerVerdict.FLOOR_UNREACHABLE,
                cause=CauseClass.COMPUTE,
                session_id=session_id,
                attempt=attempt,
                close_session=True,
                detail="compute_retry_would_breach_floor",
            )
        return ControllerDecision(
            verdict=ControllerVerdict.EXTEND_TIMEOUT,
            cause=CauseClass.COMPUTE,
            session_id=session_id,
            attempt=attempt,
            detail=f"compute:extended_timeout={attempt}/{self._max_compute}",
        )
