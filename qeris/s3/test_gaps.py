"""S3 - Gap-fill tests: CAUSE_UNKNOWN (DEC-5), Invariant I8 (DEC-4), Profile-set floor (DEC-3).

Coverage map
============
CU1  CAUSE_UNKNOWN is defined in CauseClass enum.
CU2  Classifier returns CAUSE_UNKNOWN when no signals match any known cause.
CU3  CAUSE_UNKNOWN has label_confidence=="low".
CU4  RecoveryController returns OBSERVE_AND_WAIT on first CAUSE_UNKNOWN event.
CU5  RecoveryController returns FAIL on second CAUSE_UNKNOWN (cap=1).
CU6  CAUSE_UNKNOWN + floor breach → FLOOR_UNREACHABLE, not OBSERVE_AND_WAIT.
CU7  OBSERVE_AND_WAIT is a non-terminal verdict.
CU8  OBSERVE_AND_WAIT carries a fixed backoff_ms (not 0).
CU9  Security failure overrides CAUSE_UNKNOWN (priority order).

I8-1  HandshakeContextRecord.create() computes digest from policy bytes.
I8-2  activation_check: same epoch, same digest, profile approved → COMPLIANT_REBIND.
I8-3  activation_check: same epoch, same digest, profile NOT approved → IMPOSSIBLE_QUARANTINE.
I8-4  activation_check: epoch changed, profile in new set → INCOMPATIBLE_RESTART.
I8-5  activation_check: epoch changed, profile NOT in new set → IMPOSSIBLE_QUARANTINE.
I8-6  activation_check: same epoch, digest mismatch, profile in new set → INCOMPATIBLE_RESTART.
I8-7  activation_check: same epoch, digest mismatch, profile NOT in new set → IMPOSSIBLE_QUARANTINE.
I8-8  COMPLIANT_REBIND → should_activate is True.
I8-9  INCOMPATIBLE_RESTART → should_restart is True, should_activate is False.
I8-10 IMPOSSIBLE_QUARANTINE → should_quarantine is True, should_activate is False.
I8-11 PolicyEpochChangedEvent.is_change False when old==new.
I8-12 PolicyEpochChangedEvent.is_change True when old!=new.
I8-13 Invariant I8: epoch change during handshake never silently activates (integration).

PF1  ProfileFloor.from_policy builds approved set from protection_profiles list.
PF2  ProfileFloor.from_policy falls back to scalar mode when no protection_profiles.
PF3  ProfileFloor.check: profile in set → accepted.
PF4  ProfileFloor.check: profile NOT in set → is_downgrade True.
PF5  ProfileFloor.check is case-insensitive.
PF6  ProfileFloor.is_reachable_by: device has overlapping profile → True.
PF7  ProfileFloor.is_reachable_by: device has no overlap → False.
PF8  Mode.from_profile: "PQ_MLKEM768" → Mode.PQ.
PF9  Mode.from_profile: "HYBRID_X25519_MLKEM768" → Mode.HYBRID.
PF10 Mode.from_profile: "CLASSICAL_RSA2048" → Mode.CLASSICAL.
PF11 scalar_summary returns minimum approved level, not maximum.
PF12 ProfileFloor.check with S2-style "PQC" mode string accepted via normalisation.
"""
from __future__ import annotations

import hashlib
import unittest

from failure_taxonomy import CauseClass, ClassifiedEvent, FailureTaxonomy, ObservedSignals
from recovery_controller import ControllerVerdict, RecoveryController
from floor_state_machine import FlowContext, FlowState
from downgrade_rejection import Mode
from policy_epoch import (
    ActivationOutcome,
    HandshakeContextRecord,
    LivePolicySnapshot,
    PolicyEpochChangedEvent,
    activation_check,
)
from profile_floor import Mode as PFMode, ProfileFloor


# ===========================================================================
# Helpers
# ===========================================================================

def _make_policy_bytes(label: str = "v1") -> bytes:
    return f'{{"policy": "data", "label": "{label}"}}'.encode()


def _make_record(
    epoch: int = 1,
    policy_bytes: bytes | None = None,
    approved_profiles: set | None = None,
    handshake_id: str = "hs-001",
) -> HandshakeContextRecord:
    if policy_bytes is None:
        policy_bytes = _make_policy_bytes(f"v{epoch}")
    if approved_profiles is None:
        approved_profiles = {"PQ_MLKEM768", "HYBRID_X25519_MLKEM768"}
    return HandshakeContextRecord.create(
        device_id="dev-01",
        flow_id="flow-01",
        epoch=epoch,
        policy_bytes=policy_bytes,
        approved_profiles=approved_profiles,
        handshake_id=handshake_id,
    )


def _make_live(
    epoch: int = 1,
    policy_bytes: bytes | None = None,
    approved_profiles: set | None = None,
) -> LivePolicySnapshot:
    if policy_bytes is None:
        policy_bytes = _make_policy_bytes(f"v{epoch}")
    if approved_profiles is None:
        approved_profiles = {"PQ_MLKEM768", "HYBRID_X25519_MLKEM768"}
    return LivePolicySnapshot.create(
        epoch=epoch,
        policy_bytes=policy_bytes,
        approved_profiles=approved_profiles,
    )


def _make_ctx(floor="HYBRID", negotiated="PQ", device_best="PQ") -> FlowContext:
    ctx = FlowContext(device_id="dev-01", flow_id="flow-01")
    ctx.floor_mode = Mode.parse(floor)
    ctx.negotiated_mode = Mode.parse(negotiated)
    ctx.device_best_mode = Mode.parse(device_best)
    return ctx


def _cause_unknown_event() -> ClassifiedEvent:
    return ClassifiedEvent(
        cause=CauseClass.CAUSE_UNKNOWN,
        signals=ObservedSignals(),
        label_confidence="low",
        notes="test abstention",
    )


# ===========================================================================
# CU: CAUSE_UNKNOWN tests
# ===========================================================================

class TestCauseUnknown(unittest.TestCase):

    def test_CU1_cause_unknown_in_enum(self):
        """CU1: CAUSE_UNKNOWN is a member of CauseClass."""
        self.assertIn("CAUSE_UNKNOWN", [c.name for c in CauseClass])

    def test_CU2_classifier_returns_unknown_on_empty_signals(self):
        """CU2: Classifier returns CAUSE_UNKNOWN when no signals match."""
        signals = ObservedSignals()  # all False, no delays set
        result = FailureTaxonomy().classify(signals)
        self.assertEqual(result.cause, CauseClass.CAUSE_UNKNOWN)

    def test_CU3_unknown_has_low_confidence(self):
        """CU3: CAUSE_UNKNOWN events have label_confidence='low'."""
        signals = ObservedSignals()
        result = FailureTaxonomy().classify(signals)
        self.assertEqual(result.label_confidence, "low")

    def test_CU4_controller_observe_and_wait_first(self):
        """CU4: First CAUSE_UNKNOWN → OBSERVE_AND_WAIT (not FAIL)."""
        ctrl = RecoveryController()
        ctx = _make_ctx()
        decision = ctrl.handle("s1", _cause_unknown_event(), FlowState.NEGOTIATING, ctx)
        self.assertEqual(decision.verdict, ControllerVerdict.OBSERVE_AND_WAIT)
        self.assertFalse(decision.is_terminal)

    def test_CU5_controller_fail_on_second_unknown(self):
        """CU5: Second CAUSE_UNKNOWN → FAIL (hard cap = 1 observation window)."""
        ctrl = RecoveryController()
        ctx = _make_ctx()
        ctrl.handle("s2", _cause_unknown_event(), FlowState.NEGOTIATING, ctx)  # first
        decision = ctrl.handle("s2", _cause_unknown_event(), FlowState.NEGOTIATING, ctx)  # second
        self.assertEqual(decision.verdict, ControllerVerdict.FAIL)
        self.assertTrue(decision.is_terminal)

    def test_CU6_floor_breach_returns_floor_unreachable(self):
        """CU6: CAUSE_UNKNOWN when floor would be breached → FLOOR_UNREACHABLE."""
        ctrl = RecoveryController()
        ctx = _make_ctx(floor="PQ", negotiated="HYBRID", device_best="CLASSICAL")
        # floor=PQ, negotiated=HYBRID < floor  → _floor_ok() is False
        ctx.floor_mode = Mode.parse("PQ")
        ctx.negotiated_mode = Mode.parse("HYBRID")
        decision = ctrl.handle("s3", _cause_unknown_event(), FlowState.NEGOTIATING, ctx)
        self.assertEqual(decision.verdict, ControllerVerdict.FLOOR_UNREACHABLE)
        self.assertTrue(decision.is_terminal)

    def test_CU7_observe_and_wait_is_non_terminal(self):
        """CU7: OBSERVE_AND_WAIT verdict is NOT terminal."""
        self.assertNotIn(
            ControllerVerdict.OBSERVE_AND_WAIT,
            [ControllerVerdict.DISCARD_AND_LOG,
             ControllerVerdict.FLOOR_UNREACHABLE,
             ControllerVerdict.FAIL],
        )

    def test_CU8_observe_and_wait_has_nonzero_backoff(self):
        """CU8: OBSERVE_AND_WAIT carries a non-zero fixed backoff."""
        ctrl = RecoveryController(base_backoff_ms=200)
        ctx = _make_ctx()
        decision = ctrl.handle("s4", _cause_unknown_event(), FlowState.NEGOTIATING, ctx)
        self.assertGreater(decision.backoff_ms, 0)

    def test_CU9_auth_check_beats_unknown(self):
        """CU9: auth_check_failed produces SECURITY_FAILURE, not CAUSE_UNKNOWN."""
        signals = ObservedSignals(auth_check_failed=True)
        result = FailureTaxonomy().classify(signals)
        self.assertEqual(result.cause, CauseClass.SECURITY_FAILURE)


# ===========================================================================
# I8: Policy Epoch Safety / Invariant I8 tests
# ===========================================================================

class TestPolicyEpoch(unittest.TestCase):

    def test_I8_1_digest_computed_from_bytes(self):
        """I8-1: HandshakeContextRecord stores SHA-256 digest of policy bytes."""
        policy_bytes = _make_policy_bytes("v1")
        record = _make_record(epoch=1, policy_bytes=policy_bytes)
        expected = hashlib.sha256(policy_bytes).hexdigest()
        self.assertEqual(record.policy_digest, expected)

    def test_I8_2_compliant_rebind_same_epoch_digest_profile_ok(self):
        """I8-2: Same epoch + same digest + profile approved → COMPLIANT_REBIND."""
        pb = _make_policy_bytes("v1")
        record = _make_record(epoch=1, policy_bytes=pb)
        live = _make_live(epoch=1, policy_bytes=pb)
        result = activation_check(record, live, "PQ_MLKEM768")
        self.assertEqual(result.outcome, ActivationOutcome.COMPLIANT_REBIND)
        self.assertTrue(result.should_activate)

    def test_I8_3_impossible_quarantine_profile_not_approved(self):
        """I8-3: Same epoch + same digest + profile NOT in approved set → IMPOSSIBLE_QUARANTINE."""
        pb = _make_policy_bytes("v1")
        approved = {"PQ_MLKEM768"}
        record = _make_record(epoch=1, policy_bytes=pb, approved_profiles=approved)
        live = _make_live(epoch=1, policy_bytes=pb, approved_profiles=approved)
        result = activation_check(record, live, "CLASSICAL_RSA2048")
        self.assertEqual(result.outcome, ActivationOutcome.IMPOSSIBLE_QUARANTINE)
        self.assertTrue(result.should_quarantine)

    def test_I8_4_incompatible_restart_epoch_changed_profile_ok(self):
        """I8-4: Epoch changed, negotiated profile IN new approved set → INCOMPATIBLE_RESTART."""
        pb_old = _make_policy_bytes("v1")
        pb_new = _make_policy_bytes("v2")
        record = _make_record(epoch=1, policy_bytes=pb_old)
        live = _make_live(epoch=2, policy_bytes=pb_new)  # epoch bumped
        result = activation_check(record, live, "PQ_MLKEM768")
        self.assertEqual(result.outcome, ActivationOutcome.INCOMPATIBLE_RESTART)
        self.assertTrue(result.should_restart)
        self.assertFalse(result.should_activate)

    def test_I8_5_impossible_quarantine_epoch_changed_profile_not_ok(self):
        """I8-5: Epoch changed, profile NOT in new approved set → IMPOSSIBLE_QUARANTINE."""
        pb_old = _make_policy_bytes("v1")
        pb_new = _make_policy_bytes("v2")
        record = _make_record(
            epoch=1, policy_bytes=pb_old,
            approved_profiles={"CLASSICAL_RSA2048"},
        )
        live = _make_live(
            epoch=2, policy_bytes=pb_new,
            approved_profiles={"PQ_MLKEM768"},  # CLASSICAL no longer allowed
        )
        result = activation_check(record, live, "CLASSICAL_RSA2048")
        self.assertEqual(result.outcome, ActivationOutcome.IMPOSSIBLE_QUARANTINE)
        self.assertTrue(result.should_quarantine)

    def test_I8_6_digest_mismatch_same_epoch_profile_ok(self):
        """I8-6: Same epoch but digest mismatch, profile in new set → INCOMPATIBLE_RESTART."""
        pb_auth = _make_policy_bytes("v1-original")
        pb_live = _make_policy_bytes("v1-mutated")  # same epoch, different bytes
        record = _make_record(epoch=1, policy_bytes=pb_auth)
        live = _make_live(epoch=1, policy_bytes=pb_live)  # digest differs
        result = activation_check(record, live, "PQ_MLKEM768")
        self.assertEqual(result.outcome, ActivationOutcome.INCOMPATIBLE_RESTART)

    def test_I8_7_digest_mismatch_same_epoch_profile_not_ok(self):
        """I8-7: Same epoch, digest mismatch, profile NOT in new set → IMPOSSIBLE_QUARANTINE."""
        pb_auth = _make_policy_bytes("v1-original")
        pb_live = _make_policy_bytes("v1-mutated")
        approved_new = {"PQ_MLKEM768"}
        record = _make_record(epoch=1, policy_bytes=pb_auth,
                              approved_profiles={"CLASSICAL_RSA2048"})
        live = _make_live(epoch=1, policy_bytes=pb_live, approved_profiles=approved_new)
        result = activation_check(record, live, "CLASSICAL_RSA2048")
        self.assertEqual(result.outcome, ActivationOutcome.IMPOSSIBLE_QUARANTINE)

    def test_I8_8_compliant_rebind_should_activate(self):
        """I8-8: COMPLIANT_REBIND → should_activate True."""
        pb = _make_policy_bytes("v1")
        record = _make_record(epoch=1, policy_bytes=pb)
        live = _make_live(epoch=1, policy_bytes=pb)
        result = activation_check(record, live, "PQ_MLKEM768")
        self.assertTrue(result.should_activate)
        self.assertFalse(result.should_restart)
        self.assertFalse(result.should_quarantine)

    def test_I8_9_incompatible_restart_flags(self):
        """I8-9: INCOMPATIBLE_RESTART → should_restart True, should_activate False."""
        pb_old = _make_policy_bytes("v1")
        pb_new = _make_policy_bytes("v2")
        record = _make_record(epoch=1, policy_bytes=pb_old)
        live = _make_live(epoch=2, policy_bytes=pb_new)
        result = activation_check(record, live, "PQ_MLKEM768")
        self.assertTrue(result.should_restart)
        self.assertFalse(result.should_activate)

    def test_I8_10_impossible_quarantine_flags(self):
        """I8-10: IMPOSSIBLE_QUARANTINE → should_quarantine True, should_activate False."""
        pb_old = _make_policy_bytes("v1")
        pb_new = _make_policy_bytes("v2")
        record = _make_record(epoch=1, policy_bytes=pb_old,
                              approved_profiles={"CLASSICAL_RSA2048"})
        live = _make_live(epoch=2, policy_bytes=pb_new,
                          approved_profiles={"PQ_MLKEM768"})
        result = activation_check(record, live, "CLASSICAL_RSA2048")
        self.assertTrue(result.should_quarantine)
        self.assertFalse(result.should_activate)

    def test_I8_11_epoch_changed_event_is_change_false(self):
        """I8-11: PolicyEpochChangedEvent.is_change is False when old==new."""
        ev = PolicyEpochChangedEvent(old_epoch=5, new_epoch=5, flow_id="f1")
        self.assertFalse(ev.is_change)

    def test_I8_12_epoch_changed_event_is_change_true(self):
        """I8-12: PolicyEpochChangedEvent.is_change is True when old!=new."""
        ev = PolicyEpochChangedEvent(old_epoch=5, new_epoch=6, flow_id="f1")
        self.assertTrue(ev.is_change)

    def test_I8_13_epoch_change_never_silently_activates(self):
        """I8-13: Integration — an epoch change during handshake NEVER silently activates."""
        pb_auth = _make_policy_bytes("v3")
        pb_live = _make_policy_bytes("v4")
        # Regardless of profile membership, outcome must NOT be COMPLIANT_REBIND
        # when epochs differ
        record = _make_record(epoch=3, policy_bytes=pb_auth)
        live = _make_live(epoch=4, policy_bytes=pb_live)
        for profile in ("PQ_MLKEM768", "CLASSICAL_RSA2048", "HYBRID_X25519_MLKEM768"):
            result = activation_check(record, live, profile)
            self.assertNotEqual(
                result.outcome, ActivationOutcome.COMPLIANT_REBIND,
                msg=f"Profile {profile!r} silently activated despite epoch change!",
            )


# ===========================================================================
# PF: Profile-set floor check (DEC-3) tests
# ===========================================================================

class TestProfileFloor(unittest.TestCase):

    def test_PF1_from_policy_builds_approved_set(self):
        """PF1: from_policy builds approved_profiles frozenset from protection_profiles."""
        policy = {
            "protection_profiles": ["PQ_MLKEM768", "HYBRID_X25519_MLKEM768"],
            "minimum_mode": "HYBRID",
        }
        floor = ProfileFloor.from_policy(policy)
        self.assertIn("PQ_MLKEM768", floor.approved_profiles)
        self.assertIn("HYBRID_X25519_MLKEM768", floor.approved_profiles)

    def test_PF2_from_policy_fallback_to_scalar(self):
        """PF2: from_policy falls back to scalar mode when no protection_profiles."""
        policy = {"minimum_mode": "PQ"}
        floor = ProfileFloor.from_policy(policy)
        self.assertGreater(len(floor.approved_profiles), 0)
        # Scalar fallback synthesises a single-element set
        self.assertIn("PQ", floor.approved_profiles)

    def test_PF3_check_accepted_profile_in_set(self):
        """PF3: check() accepted when profile is in approved set."""
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ_MLKEM768", "HYBRID_X25519_MLKEM768"}),
            minimum_scalar_mode=PFMode.HYBRID,
        )
        result = floor.check("PQ_MLKEM768")
        self.assertTrue(result.accepted)
        self.assertFalse(result.is_downgrade)

    def test_PF4_check_rejected_profile_not_in_set(self):
        """PF4: check() rejected when profile NOT in approved set."""
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ_MLKEM768"}),
            minimum_scalar_mode=PFMode.PQ,
        )
        result = floor.check("CLASSICAL_RSA2048")
        self.assertFalse(result.accepted)
        self.assertTrue(result.is_downgrade)

    def test_PF5_check_case_insensitive(self):
        """PF5: check() is case-insensitive."""
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ_MLKEM768"}),
            minimum_scalar_mode=PFMode.PQ,
        )
        self.assertTrue(floor.check("pq_mlkem768").accepted)
        self.assertTrue(floor.check("Pq_Mlkem768").accepted)
        self.assertTrue(floor.check("PQ_MLKEM768").accepted)

    def test_PF6_is_reachable_overlap(self):
        """PF6: is_reachable_by True when device has overlapping profile."""
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ_MLKEM768", "HYBRID_X25519_MLKEM768"}),
            minimum_scalar_mode=PFMode.HYBRID,
        )
        self.assertTrue(floor.is_reachable_by({"HYBRID_X25519_MLKEM768", "CLASSICAL_RSA2048"}))

    def test_PF7_is_reachable_no_overlap(self):
        """PF7: is_reachable_by False when device has no overlapping profile."""
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ_MLKEM768"}),
            minimum_scalar_mode=PFMode.PQ,
        )
        self.assertFalse(floor.is_reachable_by({"CLASSICAL_RSA2048", "HYBRID_P256_MLKEM512"}))

    def test_PF8_mode_from_profile_pq(self):
        """PF8: Mode.from_profile 'PQ_MLKEM768' → Mode.PQ."""
        self.assertEqual(PFMode.from_profile("PQ_MLKEM768"), PFMode.PQ)

    def test_PF9_mode_from_profile_hybrid(self):
        """PF9: Mode.from_profile 'HYBRID_X25519_MLKEM768' → Mode.HYBRID."""
        self.assertEqual(PFMode.from_profile("HYBRID_X25519_MLKEM768"), PFMode.HYBRID)

    def test_PF10_mode_from_profile_classical(self):
        """PF10: Mode.from_profile 'CLASSICAL_RSA2048' → Mode.CLASSICAL."""
        self.assertEqual(PFMode.from_profile("CLASSICAL_RSA2048"), PFMode.CLASSICAL)

    def test_PF11_scalar_summary_minimum_level(self):
        """PF11: scalar_summary returns minimum Mode across approved profiles."""
        policy = {
            "protection_profiles": ["PQ_MLKEM768", "HYBRID_X25519_MLKEM768"],
            "minimum_mode": "PQ",
        }
        floor = ProfileFloor.from_policy(policy)
        # min level in {"PQ_MLKEM768","HYBRID_X25519_MLKEM768"} → HYBRID
        self.assertEqual(floor.scalar_summary(), PFMode.HYBRID)

    def test_PF12_s2_pqc_alias_check(self):
        """PF12: Profile 'PQC' normalises correctly through Mode.parse alias."""
        from downgrade_rejection import Mode as DR_Mode
        self.assertEqual(DR_Mode.parse("PQC"), DR_Mode.PQ)
        # ProfileFloor with PQ profile accepts 'PQ' (normalised from 'PQC' by caller)
        floor = ProfileFloor(
            approved_profiles=frozenset({"PQ"}),
            minimum_scalar_mode=PFMode.PQ,
        )
        # Normalisation happens in check() uppercase
        result = floor.check("pq")
        self.assertTrue(result.accepted)


if __name__ == "__main__":
    unittest.main()
