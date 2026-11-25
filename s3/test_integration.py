"""S3 - Integration tests covering alignment with S1 and S2 interfaces.

Tests in this file verify every identified cross-component boundary:

  Hook tests (HK)
  ----------------
  HK1 : ALLOW decision passes through unchanged when no signals.
  HK2 : S2's "PQC" mode string is accepted (Mode alias fix).
  HK3 : FLOOR_UNREACHABLE from S2 produces FLOOR_UNREACHABLE result.
  HK4 : REJECT with "floor"/"mode" reason sets mode_below_floor signal.
  HK5 : Untrusted authority_id → REJECT with security_failure cause.
  HK6 : ALLOW where requested < floor → downgrade caught and rejected.
  HK7 : s1_status INVALID_SIGNATURE → REJECT (security_failure/bad_signature).
  HK8 : s1_status STALE_POLICY → REJECT (security_failure/replayed_version).
  HK9 : s1_status WRONG_ALGORITHM → REJECT (security_failure/revoked_algorithm).
  HK10: s1_status INVALID_STRUCTURE → REJECT (security_failure/invalid_format).
  HK11: VALID s1_status → no extra signal, ALLOW survives.
  HK12: S2 REJECT with generic reason → loss/timeout cause, retry path.
  HK13: S2 REJECT after retry cap → FAIL (terminal).
  HK14: log_gateway_decision emits S2-compatible field set.
  HK15: Mode.parse("PQC") == Mode.PQ (alias test).
  HK16: Mode.parse("HYBRID") == Mode.HYBRID (normal path).
  HK17: Mode.parse("pqc") == Mode.PQ (case-insensitive alias).

  ObservedSignals.from_s1_status tests (OS)
  -------------------------------------------
  OS1 : INVALID_SIGNATURE → auth_check_failed
  OS2 : STALE_POLICY → version_check_failed
  OS3 : WRONG_ALGORITHM → revoked_algorithm
  OS4 : UNSUPPORTED_ALGORITHM → revoked_algorithm
  OS5 : INVALID_STRUCTURE → invalid_format
  OS6 : VALID → all False
  OS7 : unknown string → all False (no crash)

  AuditLogger.log_gateway_decision tests (AL)
  ---------------------------------------------
  AL1 : ALLOW decision emits record with all S2 fields.
  AL2 : REJECT decision emits record.
  AL3 : cause_label and s3_verdict appear when provided.
  AL4 : Fields are present: device_id, flow_id, sensitivity,
        minimum_mode, requested_mode, policy_version, decision, reason.
"""
from __future__ import annotations

import io
import json
import unittest

from audit_logger import AuditLogger
from downgrade_rejection import Mode
from failure_taxonomy import CauseClass, FailureTaxonomy, ObservedSignals, SecurityReason
from s3_gateway_hook import S3GatewayHook, TRUSTED_AUTHORITIES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hook(sink=None, rate_limit=0) -> S3GatewayHook:
    buf = sink if sink is not None else io.StringIO()
    return S3GatewayHook(
        audit_level="detailed",
        rate_limit_per_min=rate_limit,
        logger_sink=buf,
    )


def _allow_gw(
    device_id="dev-01",
    flow_id="telemetry",
    sensitivity="LOW",
    minimum_mode="HYBRID",
    requested_mode="PQC",
    policy_version=3,
    authority_id="QERIS-GATEWAY",
):
    return {
        "device_id": device_id,
        "flow_id": flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "requested_mode": requested_mode,
        "policy_version": policy_version,
        "decision": "ALLOW",
        "reason": "Policy and device capability satisfied",
        "authority_id": authority_id,
    }


def _reject_gw(**overrides):
    base = _allow_gw()
    base["decision"] = "REJECT"
    base["reason"] = "Requested mode is below security floor"
    base.update(overrides)
    return base


def _read_last_log(buf: io.StringIO) -> dict:
    buf.seek(0)
    lines = [l.strip() for l in buf.getvalue().splitlines() if l.strip()]
    return json.loads(lines[-1]) if lines else {}


# ===========================================================================
# HK: Gateway Hook tests
# ===========================================================================

class TestHK_ModeAlias(unittest.TestCase):
    """HK15-17: Mode.parse alias for "PQC"."""

    def test_HK15_parse_PQC_equals_PQ(self):
        self.assertEqual(Mode.parse("PQC"), Mode.PQ)

    def test_HK16_parse_HYBRID(self):
        self.assertEqual(Mode.parse("HYBRID"), Mode.HYBRID)

    def test_HK17_parse_pqc_lowercase(self):
        self.assertEqual(Mode.parse("pqc"), Mode.PQ)

    def test_parse_classical(self):
        self.assertEqual(Mode.parse("CLASSICAL"), Mode.CLASSICAL)

    def test_parse_unknown_raises(self):
        with self.assertRaises(ValueError):
            Mode.parse("QUANTUM")

    def test_pq_canonical_still_works(self):
        self.assertEqual(Mode.parse("PQ"), Mode.PQ)


class TestHK_AllowPassthrough(unittest.TestCase):
    """HK1, HK2: Clean ALLOW, including S2 "PQC" mode strings."""

    def test_HK1_allow_passthrough(self):
        hook = _make_hook()
        gw = _allow_gw(minimum_mode="HYBRID", requested_mode="HYBRID")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "ALLOW")
        self.assertFalse(result.close_session)

    def test_HK2_PQC_mode_string_accepted(self):
        hook = _make_hook()
        gw = _allow_gw(minimum_mode="PQC", requested_mode="PQC")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "ALLOW")
        self.assertFalse(result.close_session)

    def test_allow_sets_no_cause_label(self):
        hook = _make_hook()
        gw = _allow_gw()
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.cause_label, "none")
        self.assertIsNone(result.security_reason)


class TestHK_FloorUnreachable(unittest.TestCase):
    """HK3: FLOOR_UNREACHABLE from S2."""

    def test_HK3_floor_unreachable_propagates(self):
        hook = _make_hook()
        gw = _allow_gw()
        gw["decision"] = "FLOOR_UNREACHABLE"
        gw["reason"] = "Security floor is unreachable for this device"
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "FLOOR_UNREACHABLE")
        self.assertTrue(result.close_session)
        self.assertEqual(result.s3_verdict, "FLOOR_UNREACHABLE")


class TestHK_RejectWithFloorReason(unittest.TestCase):
    """HK4: REJECT where reason mentions floor/mode."""

    def test_HK4_floor_reason_sets_mode_below_floor(self):
        hook = _make_hook()
        gw = _reject_gw(
            minimum_mode="PQC",
            requested_mode="CLASSICAL",
            reason="Requested mode is below security floor",
        )
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "REJECT")
        self.assertTrue(result.close_session)
        self.assertEqual(result.cause_label, CauseClass.SECURITY_FAILURE.value)
        self.assertEqual(result.security_reason, SecurityReason.MODE_BELOW_FLOOR.value)


class TestHK_UntrustedAuthority(unittest.TestCase):
    """HK5: Unknown authority_id → security failure."""

    def test_HK5_untrusted_authority_rejected(self):
        hook = _make_hook()
        gw = _allow_gw(authority_id="EVIL-CA")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "REJECT")
        self.assertTrue(result.close_session)
        self.assertEqual(result.cause_label, CauseClass.SECURITY_FAILURE.value)
        self.assertEqual(result.security_reason, SecurityReason.UNKNOWN_AUTHORITY.value)

    def test_trusted_authority_passes(self):
        hook = _make_hook()
        gw = _allow_gw(authority_id="QERIS-GATEWAY")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "ALLOW")


class TestHK_DowngradeCatch(unittest.TestCase):
    """HK6: S2 says ALLOW but requested < floor — S3 catches it."""

    def test_HK6_s2_allow_but_downgrade_caught(self):
        hook = _make_hook()
        gw = _allow_gw(minimum_mode="PQC", requested_mode="CLASSICAL")
        gw["decision"] = "ALLOW"  # S2 made a mistake
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.cause_label, CauseClass.SECURITY_FAILURE.value)
        self.assertEqual(result.security_reason, SecurityReason.MODE_BELOW_FLOOR.value)

    def test_at_floor_is_allowed(self):
        hook = _make_hook()
        gw = _allow_gw(minimum_mode="HYBRID", requested_mode="HYBRID")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "ALLOW")

    def test_above_floor_is_allowed(self):
        hook = _make_hook()
        gw = _allow_gw(minimum_mode="CLASSICAL", requested_mode="PQC")
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "ALLOW")


class TestHK_S1StatusBridge(unittest.TestCase):
    """HK7-11: S1 PolicyVerificationStatus passed via s1_status kwarg."""

    def _run(self, s1_status, base_decision="ALLOW"):
        hook = _make_hook()
        gw = _allow_gw()
        gw["decision"] = base_decision
        return hook.process_gateway_decision(gw, s1_status=s1_status)

    def test_HK7_invalid_signature(self):
        result = self._run("INVALID_SIGNATURE")
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.cause_label, CauseClass.SECURITY_FAILURE.value)
        self.assertEqual(result.security_reason, SecurityReason.BAD_SIGNATURE.value)

    def test_HK8_stale_policy(self):
        result = self._run("STALE_POLICY")
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.security_reason, SecurityReason.REPLAYED_VERSION.value)

    def test_HK9_wrong_algorithm(self):
        result = self._run("WRONG_ALGORITHM")
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.security_reason, SecurityReason.REVOKED_ALGORITHM.value)

    def test_HK10_invalid_structure(self):
        result = self._run("INVALID_STRUCTURE")
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.security_reason, SecurityReason.INVALID_FORMAT.value)

    def test_HK11_valid_s1_status_no_effect(self):
        result = self._run("VALID")
        self.assertEqual(result.final_decision, "ALLOW")

    def test_unsupported_algorithm(self):
        result = self._run("UNSUPPORTED_ALGORITHM")
        self.assertEqual(result.final_decision, "REJECT")
        self.assertEqual(result.security_reason, SecurityReason.REVOKED_ALGORITHM.value)


class TestHK_TransportFailureRetry(unittest.TestCase):
    """HK12-13: Generic REJECT causes retry, then hits cap."""

    def _hook_and_gw(self, max_loss=2):
        hook = S3GatewayHook(
            rate_limit_per_min=0,
            max_loss_retries=max_loss,
            logger_sink=io.StringIO(),
        )
        gw = _allow_gw()
        gw["decision"] = "REJECT"
        gw["reason"] = "timeout waiting for device"
        return hook, gw

    def test_HK12_first_reject_is_retry(self):
        hook, gw = self._hook_and_gw(max_loss=3)
        result = hook.process_gateway_decision(gw, session_id="s1")
        # no_response=True → LOSS_TIMEOUT → RETRY
        self.assertIn(result.s3_verdict, ("RETRY", "FAIL"))
        self.assertEqual(result.cause_label, CauseClass.LOSS_TIMEOUT.value)

    def test_HK13_exceeds_retry_cap(self):
        hook, gw = self._hook_and_gw(max_loss=2)
        for _ in range(2):
            hook.process_gateway_decision(gw, session_id="s99")
        result = hook.process_gateway_decision(gw, session_id="s99")
        self.assertEqual(result.s3_verdict, "FAIL")
        self.assertTrue(result.close_session)


# ===========================================================================
# OS: ObservedSignals.from_s1_status tests
# ===========================================================================

class TestOS_S1StatusBridge(unittest.TestCase):

    def test_OS1_invalid_signature(self):
        sig = ObservedSignals.from_s1_status("INVALID_SIGNATURE")
        self.assertTrue(sig.auth_check_failed)

    def test_OS2_stale_policy(self):
        sig = ObservedSignals.from_s1_status("STALE_POLICY")
        self.assertTrue(sig.version_check_failed)

    def test_OS3_wrong_algorithm(self):
        sig = ObservedSignals.from_s1_status("WRONG_ALGORITHM")
        self.assertTrue(sig.revoked_algorithm)

    def test_OS4_unsupported_algorithm(self):
        sig = ObservedSignals.from_s1_status("UNSUPPORTED_ALGORITHM")
        self.assertTrue(sig.revoked_algorithm)

    def test_OS5_invalid_structure(self):
        sig = ObservedSignals.from_s1_status("INVALID_STRUCTURE")
        self.assertTrue(sig.invalid_format)

    def test_OS6_valid_all_false(self):
        sig = ObservedSignals.from_s1_status("VALID")
        self.assertFalse(sig.auth_check_failed)
        self.assertFalse(sig.version_check_failed)
        self.assertFalse(sig.revoked_algorithm)
        self.assertFalse(sig.invalid_format)

    def test_OS7_unknown_string_no_crash(self):
        sig = ObservedSignals.from_s1_status("SOMETHING_NEW")
        # should return empty signals, not raise
        self.assertFalse(sig.auth_check_failed)

    def test_OS_case_insensitive(self):
        sig = ObservedSignals.from_s1_status("invalid_signature")
        self.assertTrue(sig.auth_check_failed)

    def test_OS_classifies_to_security(self):
        taxonomy = FailureTaxonomy()
        sig = ObservedSignals.from_s1_status("INVALID_SIGNATURE")
        event = taxonomy.classify(sig)
        self.assertEqual(event.cause, CauseClass.SECURITY_FAILURE)
        self.assertEqual(event.security_reason, SecurityReason.BAD_SIGNATURE)


# ===========================================================================
# AL: AuditLogger.log_gateway_decision tests
# ===========================================================================

class TestAL_LogGatewayDecision(unittest.TestCase):

    def _logger_and_buf(self):
        buf = io.StringIO()
        logger = AuditLogger(audit_level="detailed", rate_limit_per_min=0, sink=buf)
        return logger, buf

    def test_AL1_allow_emits_s2_fields(self):
        logger, buf = self._logger_and_buf()
        logger.log_gateway_decision(
            device_id="dev-01",
            flow_id="telemetry",
            sensitivity="LOW",
            minimum_mode="HYBRID",
            requested_mode="PQC",
            policy_version=3,
            decision="ALLOW",
            reason="Policy and device capability satisfied",
        )
        record = _read_last_log(buf)
        self.assertEqual(record["device_id"], "dev-01")
        self.assertEqual(record["flow_id"], "telemetry")
        self.assertEqual(record["sensitivity"], "LOW")
        self.assertEqual(record["minimum_mode"], "HYBRID")
        self.assertEqual(record["requested_mode"], "PQC")
        self.assertEqual(record["policy_version"], 3)
        self.assertEqual(record["decision"], "ALLOW")
        self.assertIn("reason", record)

    def test_AL2_reject_emits_record(self):
        logger, buf = self._logger_and_buf()
        logger.log_gateway_decision(
            device_id="dev-02",
            flow_id="control",
            sensitivity="CRITICAL",
            minimum_mode="PQC",
            requested_mode="CLASSICAL",
            policy_version=1,
            decision="REJECT",
            reason="Requested mode is below security floor",
        )
        record = _read_last_log(buf)
        self.assertEqual(record["decision"], "REJECT")
        self.assertEqual(record["device_id"], "dev-02")

    def test_AL3_cause_and_verdict_present(self):
        logger, buf = self._logger_and_buf()
        logger.log_gateway_decision(
            device_id="dev-03",
            flow_id="telemetry",
            sensitivity="LOW",
            minimum_mode="HYBRID",
            requested_mode="CLASSICAL",
            policy_version=2,
            decision="REJECT",
            reason="mode_below_floor",
            cause_label="security_failure",
            s3_verdict="DISCARD_AND_LOG",
        )
        record = _read_last_log(buf)
        self.assertEqual(record.get("cause_label"), "security_failure")
        self.assertEqual(record.get("s3_verdict"), "DISCARD_AND_LOG")

    def test_AL4_all_s2_fields_present(self):
        """Verify that every field from S2's gateway_logs.jsonl is present."""
        logger, buf = self._logger_and_buf()
        logger.log_gateway_decision(
            device_id="dev-04",
            flow_id="firmware",
            sensitivity="HIGH",
            minimum_mode="HYBRID",
            requested_mode="HYBRID",
            policy_version=7,
            decision="ALLOW",
            reason="ok",
        )
        record = _read_last_log(buf)
        # S2's exact field names from gateway_logs.jsonl / write_log()
        for field in ("device_id", "flow_id", "sensitivity", "minimum_mode",
                      "requested_mode", "policy_version", "decision", "reason"):
            self.assertIn(field, record, msg=f"Missing S2 field: {field!r}")

    def test_AL_floor_unreachable_emits_security_severity(self):
        logger, buf = self._logger_and_buf()
        logger.log_gateway_decision(
            device_id="dev-05",
            flow_id="control",
            sensitivity="CRITICAL",
            minimum_mode="PQC",
            requested_mode="CLASSICAL",
            policy_version=1,
            decision="FLOOR_UNREACHABLE",
            reason="device cannot reach PQC",
        )
        record = _read_last_log(buf)
        self.assertEqual(record["decision"], "FLOOR_UNREACHABLE")
        # SECURITY_FAILURE event maps to SECURITY severity
        self.assertEqual(record["severity"], "SECURITY")


# ===========================================================================
# Full end-to-end scenario (mirrors S2's Demo 1 and Demo 2)
# ===========================================================================

class TestE2E_Demo1And2(unittest.TestCase):
    """Mirror S2's Demo 1 (LOW flow, ALLOW) and Demo 2 (CRITICAL, downgrade)."""

    def test_demo1_low_flow_allow(self):
        """Demo 1: LOW-sensitivity flow, device asks HYBRID, floor HYBRID → ALLOW."""
        buf = io.StringIO()
        hook = S3GatewayHook(audit_level="standard", rate_limit_per_min=0, logger_sink=buf)
        gw = {
            "device_id": "sensor-01",
            "flow_id": "telemetry",
            "sensitivity": "LOW",
            "minimum_mode": "HYBRID",
            "requested_mode": "HYBRID",
            "policy_version": 1,
            "decision": "ALLOW",
            "reason": "Policy and device capability satisfied",
            "authority_id": "QERIS-GATEWAY",
        }
        result = hook.process_gateway_decision(gw, s1_status="VALID")
        self.assertEqual(result.final_decision, "ALLOW")
        self.assertFalse(result.close_session)
        # Audit log must have been written
        buf.seek(0)
        self.assertIn("ALLOW", buf.getvalue())

    def test_demo2_critical_flow_classical_rejected(self):
        """Demo 2: CRITICAL flow, floor PQC, device requests CLASSICAL → REJECT."""
        buf = io.StringIO()
        hook = S3GatewayHook(audit_level="standard", rate_limit_per_min=0, logger_sink=buf)
        gw = {
            "device_id": "actuator-01",
            "flow_id": "control",
            "sensitivity": "CRITICAL",
            "minimum_mode": "PQC",
            "requested_mode": "CLASSICAL",
            "policy_version": 2,
            "decision": "REJECT",
            "reason": "Requested mode is below security floor",
            "authority_id": "QERIS-GATEWAY",
        }
        result = hook.process_gateway_decision(gw)
        self.assertEqual(result.final_decision, "REJECT")
        self.assertTrue(result.close_session)
        self.assertEqual(result.cause_label, CauseClass.SECURITY_FAILURE.value)
        self.assertEqual(result.security_reason, SecurityReason.MODE_BELOW_FLOOR.value)

    def test_s2_pqc_mode_string_roundtrip(self):
        """S2 uses 'PQC' string throughout; S3 must parse it without error."""
        buf = io.StringIO()
        hook = S3GatewayHook(audit_level="standard", rate_limit_per_min=0, logger_sink=buf)
        # Simulate S2's exact response dict for a PQC flow
        gw = {
            "device_id": "camera-01",
            "flow_id": "firmware",
            "sensitivity": "CRITICAL",
            "minimum_mode": "PQC",
            "requested_mode": "PQC",
            "policy_version": 5,
            "decision": "ALLOW",
            "reason": "Policy and device capability satisfied",
            "authority_id": "QERIS-GATEWAY",
        }
        result = hook.process_gateway_decision(gw, device_best_mode="PQC")
        self.assertEqual(result.final_decision, "ALLOW")


if __name__ == "__main__":
    unittest.main()
