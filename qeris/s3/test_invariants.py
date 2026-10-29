"""S3 - Task T25: Invariant Tests and Attack Tests

All seven invariants each have at least one dedicated test.
All attack scenarios from S3 spec §F are scripted.

Invariant tests
---------------
I1: Flow never Active below its signed floor.
I2: Invalid/stale/untrusted policy cannot authorize a transition.
I3: Transport retry cannot change the security floor.
I4: Recovery cannot convert a crypto failure into a transport failure.
I5: Gateway restart cannot erase replay-protection state.
I6: Device-provided flow label cannot override gateway policy.
I7: Observed network failure cannot authorize an insecure downgrade.

Attack tests (§F)
-----------------
A1: Invalid signature → rejected and logged.
A2: Modified policy → rejected (bad signature).
A3: Replayed policy (old version) → rejected.
A4: Equal version (same as current) → rejected.
A5: Downgrade attempt on Critical flow → rejected.
A6: Unknown authority → rejected.
A7: Fake handshakes (no prior policy) → rejected.
A8: Restart then replay → still rejected (state persisted).
A9: Policy update during active session with raised floor → session closed.

Taxonomy and Controller tests
------------------------------
TC1-TC8: Cause classification correctness.
RC1-RC8: Controller verdict correctness and floor-bounded guarantee.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from downgrade_rejection import DowngradeRejector, Mode
from failure_taxonomy import (
    CauseClass, ClassifiedEvent, FailureTaxonomy, ObservedSignals, SecurityReason,
)
from floor_state_machine import (
    Action, ActionKind, Event, EventKind, FlowContext, FlowState,
    InvariantMonitor, InvariantViolation, transition,
)
from recovery_controller import ControllerDecision, ControllerVerdict, RecoveryController
from replay_protection import ReplayCheckResult, ReplayProtection


# ============================================================ helpers =======

def make_ctx(
    device_id: str = "dev-01",
    flow_id: str = "flow-01",
    floor: str | None = "HYBRID",
    negotiated: str | None = None,
    device_best: str | None = "PQ",
) -> FlowContext:
    ctx = FlowContext(device_id=device_id, flow_id=flow_id)
    if floor:
        ctx.floor_mode = Mode.parse(floor)
    if negotiated:
        ctx.negotiated_mode = Mode.parse(negotiated)
    if device_best:
        ctx.device_best_mode = Mode.parse(device_best)
    return ctx


def policy_verified_event(version: int = 1, floor: str = "HYBRID", min_acc: int = 1) -> Event:
    return Event(
        kind=EventKind.POLICY_VERIFIED,
        version=version,
        floor_mode=floor,
        min_acceptable=min_acc,
    )


def security_failure_event(reason: str = "bad_signature") -> Event:
    return Event(kind=EventKind.SECURITY_FAILURE, reject_reason=reason)


def transport_failure_event(cause: str = "loss_timeout") -> Event:
    return Event(kind=EventKind.TRANSPORT_FAILURE, cause=cause)


def run_to_active(floor: str = "HYBRID", negotiated: str = "PQ") -> tuple[FlowState, FlowContext]:
    """Drive a flow through the full happy path to ACTIVE."""
    ctx = make_ctx(floor=None, negotiated=None, device_best="PQ")
    state = FlowState.UNREGISTERED
    state, _ = transition(state, policy_verified_event(floor=floor), ctx)
    ctx.floor_mode = Mode.parse(floor)
    state, _ = transition(state, policy_verified_event(floor=floor), ctx)
    state, _ = transition(state, Event(kind=EventKind.HANDSHAKE_STARTED, device_best_mode="PQ"), ctx)
    state, _ = transition(state, Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode=negotiated), ctx)
    ctx.negotiated_mode = Mode.parse(negotiated)
    return state, ctx


# ============================================================ I1: Floor =====

class TestInvariant1_NeverActiveBelowFloor(unittest.TestCase):
    """I1: A flow is never Active below its signed minimum security floor."""

    def test_handshake_ok_above_floor_reaches_active(self):
        ctx = make_ctx(floor="HYBRID", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="PQ"),
            ctx,
        )
        ctx.negotiated_mode = Mode.PQ
        self.assertEqual(new_state, FlowState.ACTIVE)

    def test_handshake_ok_at_floor_reaches_active(self):
        ctx = make_ctx(floor="HYBRID", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="HYBRID"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.ACTIVE)

    def test_handshake_ok_below_floor_rejected(self):
        """CLASSICAL negotiated when floor=HYBRID → must NOT reach ACTIVE."""
        ctx = make_ctx(floor="HYBRID", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="CLASSICAL"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.ACTIVE)
        action_kinds = [a.kind for a in actions]
        self.assertIn(ActionKind.CLOSE_SESSION, action_kinds)
        self.assertIn(ActionKind.LOG_SECURITY, action_kinds)

    def test_invariant_monitor_raises_on_active_below_floor(self):
        ctx = make_ctx(floor="PQ", negotiated="CLASSICAL")
        monitor = InvariantMonitor()
        with self.assertRaises(InvariantViolation) as cm:
            monitor.check(
                prev_state=FlowState.NEGOTIATING,
                event=Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="CLASSICAL"),
                new_state=FlowState.ACTIVE,
                actions=[],
                ctx=ctx,
                prev_floor=Mode.PQ,
            )
        self.assertIn("I1", str(cm.exception))

    def test_monitor_passes_when_mode_meets_floor(self):
        ctx = make_ctx(floor="HYBRID", negotiated="PQ")
        monitor = InvariantMonitor()
        # Should NOT raise
        monitor.check(
            prev_state=FlowState.NEGOTIATING,
            event=Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="PQ"),
            new_state=FlowState.ACTIVE,
            actions=[],
            ctx=ctx,
            prev_floor=Mode.HYBRID,
        )


# ============================================================ I2: Policy ====

class TestInvariant2_InvalidPolicyCannotAuthorize(unittest.TestCase):
    """I2: Invalid/stale/untrusted policy cannot authorize a transition."""

    def test_policy_rejected_keeps_registered_state(self):
        ctx = make_ctx(floor=None)
        state = FlowState.REGISTERED
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_REJECTED, reject_reason="bad_signature"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.REGISTERED)

    def test_policy_rejected_keeps_policy_valid_state(self):
        ctx = make_ctx(floor="HYBRID")
        state = FlowState.POLICY_VALID
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_REJECTED, reject_reason="stale_version"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.POLICY_VALID)

    def test_policy_without_floor_does_not_enter_negotiating(self):
        ctx = make_ctx(floor=None)
        state = FlowState.REGISTERED
        # PolicyVerified event with no floor_mode
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_VERIFIED, version=1, floor_mode=None),
            ctx,
        )
        # Should not reach POLICY_VALID (floor missing)
        self.assertNotEqual(new_state, FlowState.POLICY_VALID)


# ============================================================ I3: Transport ==

class TestInvariant3_RetryDoesNotChangeFloor(unittest.TestCase):
    """I3: A transport retry cannot change the security floor."""

    def test_transport_failure_in_active_preserves_floor(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        prev_floor = ctx.floor_mode
        state = FlowState.ACTIVE
        new_state, actions = transition(state, transport_failure_event(), ctx)
        # Floor must be unchanged
        self.assertEqual(ctx.floor_mode, prev_floor)
        self.assertEqual(new_state, FlowState.DEGRADED)

    def test_transport_failure_in_negotiating_preserves_floor(self):
        ctx = make_ctx(floor="PQ", negotiated=None)
        prev_floor = ctx.floor_mode
        state = FlowState.NEGOTIATING
        new_state, actions = transition(state, transport_failure_event(), ctx)
        self.assertEqual(ctx.floor_mode, prev_floor)

    def test_invariant_monitor_raises_if_floor_changes_on_transport(self):
        ctx = make_ctx(floor="CLASSICAL", negotiated="HYBRID")
        monitor = InvariantMonitor()
        prev_floor = Mode.PQ
        # Simulating floor being lowered after transport failure — must raise I3
        ctx.floor_mode = Mode.CLASSICAL
        with self.assertRaises(InvariantViolation) as cm:
            monitor.check(
                prev_state=FlowState.ACTIVE,
                event=transport_failure_event(),
                new_state=FlowState.DEGRADED,
                actions=[],
                ctx=ctx,
                prev_floor=prev_floor,
            )
        self.assertIn("I3", str(cm.exception))


# ============================================================ I4: Crypto ====

class TestInvariant4_CryptoFailureIsNotTransport(unittest.TestCase):
    """I4: Recovery cannot convert a crypto failure into a transport failure."""

    def test_security_failure_goes_to_quarantined_not_degraded(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        state = FlowState.ACTIVE
        new_state, actions = transition(state, security_failure_event(), ctx)
        self.assertEqual(new_state, FlowState.QUARANTINED)
        action_kinds = [a.kind for a in actions]
        self.assertNotIn(ActionKind.ALLOW_RETRY, action_kinds)
        self.assertIn(ActionKind.QUARANTINE, action_kinds)

    def test_security_failure_in_negotiating_quarantines(self):
        ctx = make_ctx(floor="PQ", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, _ = transition(state, security_failure_event("bad_signature"), ctx)
        self.assertEqual(new_state, FlowState.QUARANTINED)

    def test_controller_security_failure_is_terminal(self):
        controller = RecoveryController()
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        classified = ClassifiedEvent(
            cause=CauseClass.SECURITY_FAILURE,
            security_reason=SecurityReason.BAD_SIGNATURE,
            signals=ObservedSignals(auth_check_failed=True),
        )
        decision = controller.handle("s1", classified, FlowState.ACTIVE, ctx)
        self.assertEqual(decision.verdict, ControllerVerdict.DISCARD_AND_LOG)
        self.assertTrue(decision.is_terminal)
        self.assertTrue(decision.close_session)

    def test_invariant_monitor_raises_if_security_produces_retry(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        monitor = InvariantMonitor()
        with self.assertRaises(InvariantViolation) as cm:
            monitor.check(
                prev_state=FlowState.ACTIVE,
                event=security_failure_event(),
                new_state=FlowState.DEGRADED,
                actions=[Action(ActionKind.ALLOW_RETRY)],
                ctx=ctx,
                prev_floor=Mode.PQ,
            )
        self.assertIn("I4", str(cm.exception))


# ============================================================ I5: Restart ===

class TestInvariant5_RestartCannotEraseReplayState(unittest.TestCase):
    """I5: Gateway restart cannot erase replay-protection state."""

    def test_persisted_version_survives_reload(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "replay.json"
            rp1 = ReplayProtection(path, max_version_jump=50)
            rp1.load()
            rp1.check_and_accept(5, min_acceptable_version=1)

            # Simulate restart
            rp2 = ReplayProtection(path, max_version_jump=50)
            rp2.load()
            self.assertEqual(rp2.highest_version, 5)

    def test_replay_rejected_after_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "replay.json"
            rp1 = ReplayProtection(path)
            rp1.load()
            rp1.check_and_accept(10)

            # After restart, old version 5 must still be rejected
            rp2 = ReplayProtection(path)
            rp2.load()
            outcome = rp2.check_and_accept(5)
            self.assertEqual(outcome.result, ReplayCheckResult.REPLAYED)

    def test_state_transitions_after_restart_re_enter_registered(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        state = FlowState.ACTIVE
        new_state, actions = transition(
            state, Event(kind=EventKind.RESTART), ctx
        )
        # After restart, must re-verify policy → go to REGISTERED, not ACTIVE
        self.assertEqual(new_state, FlowState.REGISTERED)


# ============================================================ I6: Flow Label =

class TestInvariant6_DeviceLabelCannotOverridePolicy(unittest.TestCase):
    """I6: Device-provided flow label cannot override gateway policy."""

    def test_floor_always_from_ctx_not_event(self):
        """The floor in ctx comes from the signed policy, not the event payload."""
        ctx = make_ctx(floor="PQ", negotiated=None)
        state = FlowState.NEGOTIATING
        # Even if the handshake says CLASSICAL, the floor from policy (PQ) wins.
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="CLASSICAL"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.ACTIVE)

    def test_downgrade_rejector_uses_policy_floor_not_device(self):
        rejector = DowngradeRejector()
        # Device claims HYBRID is fine, but policy floor is PQ
        result = rejector.check(negotiated_mode="HYBRID", floor_mode="PQ")
        self.assertFalse(result.accepted)
        self.assertTrue(result.is_downgrade)

    def test_mode_at_floor_is_accepted(self):
        rejector = DowngradeRejector()
        result = rejector.check(negotiated_mode="PQ", floor_mode="PQ")
        self.assertTrue(result.accepted)


# ============================================================ I7: NetFail ===

class TestInvariant7_NetworkFailureCannotDowngrade(unittest.TestCase):
    """I7: An observed network failure cannot authorize an insecure downgrade."""

    def test_transport_failure_stays_degraded_not_lower_mode(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        state = FlowState.ACTIVE
        new_state, actions = transition(state, transport_failure_event(), ctx)
        # Mode and floor must be unchanged; state goes to DEGRADED (not lower mode)
        self.assertEqual(new_state, FlowState.DEGRADED)
        self.assertEqual(ctx.floor_mode, Mode.PQ)
        self.assertEqual(ctx.negotiated_mode, Mode.PQ)

    def test_controller_does_not_lower_mode_on_loss(self):
        controller = RecoveryController(max_loss_retries=3)
        ctx = make_ctx(floor="PQ", negotiated="PQ", device_best="PQ")
        classified = ClassifiedEvent(
            cause=CauseClass.LOSS_TIMEOUT,
            signals=ObservedSignals(no_response=True),
        )
        decision = controller.handle("s1", classified, FlowState.ACTIVE, ctx)
        self.assertEqual(decision.verdict, ControllerVerdict.RETRY)
        # Floor and mode must be unchanged
        self.assertEqual(ctx.floor_mode, Mode.PQ)
        self.assertEqual(ctx.negotiated_mode, Mode.PQ)

    def test_invariant_monitor_raises_if_transport_lowers_floor(self):
        # The monitor fires I3 (transport failure changed floor) when floor is
        # lowered after a transport event — I3 and I7 overlap here; both say
        # "floor must not change on transport failure".
        ctx = make_ctx(floor="CLASSICAL", negotiated="PQ")
        monitor = InvariantMonitor()
        with self.assertRaises(InvariantViolation) as cm:
            monitor.check(
                prev_state=FlowState.ACTIVE,
                event=transport_failure_event(),
                new_state=FlowState.DEGRADED,
                actions=[],
                ctx=ctx,
                prev_floor=Mode.PQ,
            )
        # I3 fires: floor changed on transport event (also covers I7's guarantee).
        self.assertIn("I3", str(cm.exception))


# ============================================================ Attack Tests ==

class TestA1_InvalidSignature(unittest.TestCase):
    """A1: Invalid signature → rejected and logged."""

    def test_policy_rejected_on_bad_signature(self):
        ctx = make_ctx(floor=None)
        state = FlowState.REGISTERED
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_REJECTED, reject_reason="bad_signature"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.REGISTERED)
        log_actions = [a for a in actions if a.kind is ActionKind.LOG_SECURITY]
        self.assertTrue(any("bad_signature" in a.detail for a in log_actions))


class TestA2_ModifiedPolicy(unittest.TestCase):
    """A2: Modified policy → rejected (signature check fails)."""

    def test_modified_policy_keeps_old_state(self):
        ctx = make_ctx(floor="PQ")
        state = FlowState.POLICY_VALID
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_REJECTED, reject_reason="bad_signature"),
            ctx,
        )
        # Must stay in POLICY_VALID with the old floor intact
        self.assertEqual(new_state, FlowState.POLICY_VALID)
        self.assertEqual(ctx.floor_mode, Mode.PQ)


class TestA3_ReplayedPolicy(unittest.TestCase):
    """A3: Replayed policy (old version) → rejected."""

    def test_old_version_rejected_by_replay_protection(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        rp.check_and_accept(5)
        outcome = rp.check_and_accept(3)
        self.assertEqual(outcome.result, ReplayCheckResult.REPLAYED)
        self.assertFalse(outcome.accepted)


class TestA4_EqualVersion(unittest.TestCase):
    """A4: Equal version (same as current) → rejected."""

    def test_same_version_rejected(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        rp.check_and_accept(5)
        outcome = rp.check_and_accept(5)
        self.assertEqual(outcome.result, ReplayCheckResult.REPLAYED)

    def test_detail_mentions_replay(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        rp.check_and_accept(5)
        outcome = rp.check_and_accept(5)
        self.assertIn("replay", outcome.detail)


class TestA5_DowngradeOnCritical(unittest.TestCase):
    """A5: Downgrade attempt on a Critical (PQ-floor) flow → rejected."""

    def test_classical_negotiated_for_pq_floor_rejected(self):
        ctx = make_ctx(floor="PQ", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="CLASSICAL"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.ACTIVE)
        self.assertIn(ActionKind.LOG_SECURITY, [a.kind for a in actions])

    def test_hybrid_negotiated_for_pq_floor_rejected(self):
        ctx = make_ctx(floor="PQ", negotiated=None)
        state = FlowState.NEGOTIATING
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_OK, negotiated_mode="HYBRID"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.ACTIVE)

    def test_downgrade_rejector_blocks_classical_on_critical(self):
        rejector = DowngradeRejector()
        result = rejector.check("CLASSICAL", "PQ")
        self.assertFalse(result.accepted)


class TestA6_UnknownAuthority(unittest.TestCase):
    """A6: Unknown authority → rejected."""

    def test_unknown_authority_triggers_security_failure(self):
        taxonomy = FailureTaxonomy()
        signals = ObservedSignals(unknown_authority=True)
        event = taxonomy.classify(signals)
        self.assertEqual(event.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(event.security_reason, SecurityReason.UNKNOWN_AUTHORITY)

    def test_security_failure_from_unknown_authority_quarantines(self):
        ctx = make_ctx(floor="PQ", negotiated="PQ")
        state = FlowState.ACTIVE
        new_state, _ = transition(
            state,
            security_failure_event("unknown_authority"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.QUARANTINED)


class TestA7_FakeHandshake(unittest.TestCase):
    """A7: Fake handshakes (no prior verified policy) → rejected."""

    def test_handshake_without_floor_rejected(self):
        ctx = make_ctx(floor=None)
        state = FlowState.POLICY_VALID
        # No floor_mode set → HandshakeStarted must not proceed
        new_state, actions = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_STARTED, device_best_mode="PQ"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.NEGOTIATING)

    def test_unregistered_device_cannot_reach_active(self):
        ctx = make_ctx(floor=None)
        state = FlowState.UNREGISTERED
        # Try to directly trigger handshake
        new_state, _ = transition(
            state,
            Event(kind=EventKind.HANDSHAKE_STARTED, device_best_mode="PQ"),
            ctx,
        )
        self.assertNotEqual(new_state, FlowState.NEGOTIATING)
        self.assertNotEqual(new_state, FlowState.ACTIVE)


class TestA8_RestartThenReplay(unittest.TestCase):
    """A8: Restart then replay → still rejected (replay state persisted)."""

    def test_restart_does_not_allow_version_replay(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "replay.json"
            rp = ReplayProtection(path)
            rp.load()
            rp.check_and_accept(10)

            # Simulate restart
            rp2 = ReplayProtection(path)
            rp2.load()
            # Try to replay version 7 (below 10)
            outcome = rp2.check_and_accept(7)
            self.assertFalse(outcome.accepted)
            self.assertEqual(outcome.result, ReplayCheckResult.REPLAYED)

    def test_restart_state_machine_goes_to_registered(self):
        state, ctx = run_to_active()
        self.assertEqual(state, FlowState.ACTIVE)
        new_state, _ = transition(state, Event(kind=EventKind.RESTART), ctx)
        self.assertEqual(new_state, FlowState.REGISTERED)


class TestA9_PolicyUpdateRaisesFloor(unittest.TestCase):
    """A9: Policy update during active session with raised floor → session closed."""

    def test_floor_raised_above_negotiated_closes_session(self):
        # Start with floor=HYBRID, mode=HYBRID
        ctx = make_ctx(floor="HYBRID", negotiated="HYBRID")
        state = FlowState.ACTIVE
        # Policy update raises floor to PQ
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_VERIFIED, version=2, floor_mode="PQ"),
            ctx,
        )
        # Session must be closed and re-negotiation required
        self.assertNotEqual(new_state, FlowState.ACTIVE)
        self.assertIn(ActionKind.CLOSE_SESSION, [a.kind for a in actions])

    def test_floor_raised_but_mode_still_meets_it_stays_active(self):
        # mode=PQ, floor raised from HYBRID to PQ — mode still meets it
        ctx = make_ctx(floor="HYBRID", negotiated="PQ")
        state = FlowState.ACTIVE
        new_state, actions = transition(
            state,
            Event(kind=EventKind.POLICY_VERIFIED, version=2, floor_mode="PQ"),
            ctx,
        )
        self.assertEqual(new_state, FlowState.ACTIVE)


# ============================================================ Taxonomy Tests =

class TestTaxonomy(unittest.TestCase):
    """TC: Failure taxonomy classification correctness."""

    def setUp(self):
        self.t = FailureTaxonomy()

    def test_auth_failed_is_security(self):
        e = self.t.classify(ObservedSignals(auth_check_failed=True))
        self.assertEqual(e.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(e.security_reason, SecurityReason.BAD_SIGNATURE)

    def test_version_check_failed_is_security(self):
        e = self.t.classify(ObservedSignals(version_check_failed=True))
        self.assertEqual(e.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(e.security_reason, SecurityReason.REPLAYED_VERSION)

    def test_fast_forward_is_security(self):
        e = self.t.classify(ObservedSignals(version_jump_exceeded=True))
        self.assertEqual(e.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(e.security_reason, SecurityReason.FAST_FORWARD_VERSION)

    def test_mode_below_floor_is_security(self):
        e = self.t.classify(ObservedSignals(mode_below_floor=True))
        self.assertEqual(e.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(e.security_reason, SecurityReason.MODE_BELOW_FLOOR)

    def test_fragment_exceeded_is_mtu(self):
        e = self.t.classify(ObservedSignals(fragment_size_exceeded=True))
        self.assertEqual(e.cause, CauseClass.MTU_FRAGMENT)

    def test_no_response_is_loss(self):
        e = self.t.classify(ObservedSignals(no_response=True))
        self.assertEqual(e.cause, CauseClass.LOSS_TIMEOUT)

    def test_security_beats_mtu(self):
        # Both auth failure and fragment exceeded — security must win
        e = self.t.classify(ObservedSignals(auth_check_failed=True, fragment_size_exceeded=True))
        self.assertEqual(e.cause, CauseClass.SECURITY_FAILURE)

    def test_empty_signals_is_loss(self):
        e = self.t.classify(ObservedSignals())
        self.assertEqual(e.cause, CauseClass.LOSS_TIMEOUT)

    def test_to_dict_has_cause(self):
        e = self.t.classify(ObservedSignals(no_response=True))
        d = e.to_dict()
        self.assertEqual(d["cause"], "loss_timeout")


# ============================================================ Replay Tests ==

class TestReplayProtection(unittest.TestCase):

    def test_first_version_accepted(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        outcome = rp.check_and_accept(1)
        self.assertTrue(outcome.accepted)

    def test_higher_version_accepted(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        rp.check_and_accept(1)
        outcome = rp.check_and_accept(2)
        self.assertTrue(outcome.accepted)

    def test_fast_forward_rejected(self):
        rp = ReplayProtection(in_memory=True, max_version_jump=10)
        rp.load()
        rp.check_and_accept(1)
        outcome = rp.check_and_accept(100)
        self.assertEqual(outcome.result, ReplayCheckResult.FAST_FORWARD)

    def test_below_min_acceptable_rejected(self):
        rp = ReplayProtection(in_memory=True)
        rp.load()
        rp.check_and_accept(5, min_acceptable_version=5)
        outcome = rp.check_and_accept(6, min_acceptable_version=10)
        self.assertEqual(outcome.result, ReplayCheckResult.BELOW_MIN)

    def test_corrupt_store_raises_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "replay.json"
            path.with_suffix(".sha256").write_text("BADHASH\n", encoding="ascii")
            path.write_bytes(b'{"highest":5,"min_acceptable":1}')
            rp = ReplayProtection(path)
            with self.assertRaises(RuntimeError):
                rp.load()


# ============================================================ Controller =====

class TestRecoveryController(unittest.TestCase):

    def setUp(self):
        self.controller = RecoveryController(
            max_loss_retries=3, max_mtu_retries=2, base_backoff_ms=100
        )

    def _ctx(self, floor="PQ", negotiated="PQ", best="PQ"):
        return make_ctx(floor=floor, negotiated=negotiated, device_best=best)

    def _loss(self):
        return ClassifiedEvent(cause=CauseClass.LOSS_TIMEOUT, signals=ObservedSignals(no_response=True))

    def _mtu(self):
        return ClassifiedEvent(cause=CauseClass.MTU_FRAGMENT, signals=ObservedSignals(fragment_size_exceeded=True))

    def _sec(self):
        return ClassifiedEvent(
            cause=CauseClass.SECURITY_FAILURE,
            security_reason=SecurityReason.BAD_SIGNATURE,
            signals=ObservedSignals(auth_check_failed=True),
        )

    def test_loss_retry(self):
        d = self.controller.handle("s1", self._loss(), FlowState.ACTIVE, self._ctx())
        self.assertEqual(d.verdict, ControllerVerdict.RETRY)
        self.assertGreater(d.backoff_ms, 0)

    def test_loss_cap(self):
        ctx = self._ctx()
        for _ in range(3):
            self.controller.handle("s1", self._loss(), FlowState.ACTIVE, ctx)
        d = self.controller.handle("s1", self._loss(), FlowState.ACTIVE, ctx)
        self.assertEqual(d.verdict, ControllerVerdict.FAIL)

    def test_mtu_refragment(self):
        d = self.controller.handle("s1", self._mtu(), FlowState.ACTIVE, self._ctx())
        self.assertEqual(d.verdict, ControllerVerdict.REFRAGMENT)

    def test_security_always_discard(self):
        for _ in range(5):
            d = self.controller.handle("s1", self._sec(), FlowState.ACTIVE, self._ctx())
            self.assertEqual(d.verdict, ControllerVerdict.DISCARD_AND_LOG)
            self.assertTrue(d.close_session)

    def test_floor_unreachable_stops_loss_retry(self):
        # Device best = CLASSICAL but floor = PQ
        ctx = self._ctx(floor="PQ", negotiated="PQ", best="CLASSICAL")
        d = self.controller.handle("s1", self._loss(), FlowState.ACTIVE, ctx)
        self.assertEqual(d.verdict, ControllerVerdict.FLOOR_UNREACHABLE)
        self.assertTrue(d.is_terminal)

    def test_backoff_increases(self):
        ctx = self._ctx()
        b1 = self.controller.handle("s2", self._loss(), FlowState.ACTIVE, ctx).backoff_ms
        b2 = self.controller.handle("s2", self._loss(), FlowState.ACTIVE, ctx).backoff_ms
        self.assertGreater(b2, b1)

    def test_reset_clears_counters(self):
        ctx = self._ctx()
        for _ in range(3):
            self.controller.handle("s3", self._loss(), FlowState.ACTIVE, ctx)
        self.controller.reset("s3")
        d = self.controller.handle("s3", self._loss(), FlowState.ACTIVE, ctx)
        self.assertEqual(d.verdict, ControllerVerdict.RETRY)

    def test_independent_sessions(self):
        ctx = self._ctx()
        for _ in range(3):
            self.controller.handle("sx", self._loss(), FlowState.ACTIVE, ctx)
        # s_new is independent — first loss should retry, not fail
        d = self.controller.handle("s_new", self._loss(), FlowState.ACTIVE, ctx)
        self.assertEqual(d.verdict, ControllerVerdict.RETRY)


# ============================================================ main ===========

if __name__ == "__main__":
    unittest.main(verbosity=2)
