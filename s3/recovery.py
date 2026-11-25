"""S3 - Recovery module (public interface for S2/S4 integration).

Re-exports the canonical types from the individual S3 modules so that
S2 and S4 can import a single well-known name:

    from recovery import RecoveryController, CauseClass, ControllerVerdict

This module is the handoff point documented in S3 spec §J (Weeks 7-8):
  "Week 8: controller interface to S2 (for adaptive baselines) and S4 (for runs)."

S2 integration hook
-------------------
The recommended integration path is via S3GatewayHook (one instance per
gateway process).  S2 calls it immediately after check_flow():

    from recovery import S3GatewayHook

    _s3 = S3GatewayHook(audit_level="standard")

    # Inside the /check-flow handler, after S2's own decision logic:
    s3_result = _s3.process_gateway_decision(
        gw_decision=response_dict,          # the dict S2 would return
        session_id=f"{device_id}:{flow_id}",
        s1_status=s1_verify_result.status.name,   # optional
        device_best_mode=max(supported_modes),     # optional
    )
    if s3_result.close_session:
        # terminate session
    response_dict["decision"] = s3_result.final_decision
    response_dict["reason"]   = s3_result.detail

Low-level integration (direct module use)
-----------------------------------------
After the classifier produces a SecurityDecision, the gateway (S2) calls:

    controller = RecoveryController(...)
    classified = taxonomy.classify(signals)
    decision = controller.handle(session_id, classified, flow_state, ctx)
    if decision.is_terminal:
        # close session; log to audit_logger
    elif decision.verdict == ControllerVerdict.RETRY:
        # schedule retransmit after decision.backoff_ms

S4 event schema
---------------
Every ClassifiedEvent returned by FailureTaxonomy.classify() carries:
  - cause      (CauseClass value string)
  - security_reason (if SECURITY_FAILURE)
  - label_confidence ("high" | "medium" | "low")
  - signals    (ObservedSignals dict for ground-truth comparison)

Forward the ClassifiedEvent.to_dict() to S4's data pipeline.

S1 bridge
---------
ObservedSignals.from_s1_status(result.status.name) translates S1's
PolicyVerificationStatus string into the correct ObservedSignals flags so
the FailureTaxonomy classifier routes it to the right CauseClass /
SecurityReason without any if/elif chain in S2.

Mode alias
----------
Mode.parse("PQC") → Mode.PQ.  S2 uses "PQC"; S3 uses "PQ" internally.
Pass S2 mode strings directly — no manual translation required.
"""
# S3 canonical exports — import from here for all cross-component use.
from failure_taxonomy import (
    CauseClass,
    ClassifiedEvent,
    FailureTaxonomy,
    ObservedSignals,
    SecurityReason,
)
from recovery_controller import (
    ControllerDecision,
    ControllerVerdict,
    RecoveryController,
)
from floor_state_machine import (
    Action,
    ActionKind,
    Event,
    EventKind,
    FlowContext,
    FlowState,
    InvariantMonitor,
    InvariantViolation,
    transition,
)
from downgrade_rejection import DowngradeRejector, DowngradeCheckResult, Mode
from replay_protection import ReplayProtection, ReplayCheckResult, ReplayCheckOutcome
from s3_gateway_hook import S3GatewayHook, S3HookResult, TRUSTED_AUTHORITIES

__all__ = [
    # Taxonomy
    "CauseClass", "ClassifiedEvent", "FailureTaxonomy",
    "ObservedSignals", "SecurityReason",
    # Controller
    "ControllerDecision", "ControllerVerdict", "RecoveryController",
    # State machine
    "Action", "ActionKind", "Event", "EventKind",
    "FlowContext", "FlowState", "InvariantMonitor", "InvariantViolation",
    "transition",
    # Downgrade
    "DowngradeRejector", "DowngradeCheckResult", "Mode",
    # Replay
    "ReplayProtection", "ReplayCheckResult", "ReplayCheckOutcome",
    # Integration hook (S2 entry point)
    "S3GatewayHook", "S3HookResult", "TRUSTED_AUTHORITIES",
]
