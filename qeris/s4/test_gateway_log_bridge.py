"""
Tests for qeris.s4.gateway_log_bridge — Stage 5 Integration
Verifies that gateway audit log entries (legacy and Phase-4) are correctly
mapped into canonical S4 LogRecord objects.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
import sys
import time
import unittest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from qeris.s4.analysis import StatisticalAnalyzer

from qeris.s4.gateway_log_bridge import (
    BridgeConfig,
    GatewayLogBridge,
    _infer_cause_label_from_reason,
)
from qeris.s4.log_schema import (
    Baseline,
    CryptoMode,
    DeviceClass,
    LogEvent,
    LogOutcome,
    LogRecord,
    SensitivityTier,
)


# ── sample payloads ─────────────────────────────────────────────────────────

PHASE4_ALLOW = {
    "trace_id": "trace_test_02",
    "ts": 1793526756920,
    "timestamp": "2026-11-01T09:52:36.920+00:00",
    "device_id": "device_002",
    "flow_id": "temperature_01",
    "sensitivity": "LOW",
    "minimum_mode": "CLASSICAL",
    "requested_mode": "PQC",
    "policy_version": 1,
    "authority_id": "QERIS-GATEWAY",
    "decision": "ALLOW",
    "reason": "Policy and device capability satisfied",
    "s3_verdict": "NONE",
    "cause_label": "none",
    "security_reason": None,
    "crypto_status": "SKIPPED",
}

PHASE4_REJECT_DOWNGRADE = {
    "trace_id": "trace_test_03",
    "ts": 1793526756921,
    "timestamp": "2026-11-01T09:52:36.921+00:00",
    "device_id": "device_001",
    "flow_id": "emergency_stop",
    "sensitivity": "CRITICAL",
    "minimum_mode": "HYBRID",
    "requested_mode": "CLASSICAL",
    "policy_version": 1,
    "authority_id": "QERIS-GATEWAY",
    "decision": "REJECT",
    "reason": "mode_below_floor",
    "s3_verdict": "DISCARD_AND_LOG",
    "cause_label": "security_failure",
    "security_reason": "mode_below_floor",
    "crypto_status": "SKIPPED",
}

PHASE4_FLOOR_UNREACHABLE = {
    "trace_id": "trace_test_04",
    "ts": 1793526756922,
    "timestamp": "2026-11-01T09:52:36.922+00:00",
    "device_id": "device_003",
    "flow_id": "emergency_stop",
    "sensitivity": "CRITICAL",
    "minimum_mode": "HYBRID",
    "requested_mode": "HYBRID",
    "policy_version": 1,
    "authority_id": "QERIS-GATEWAY",
    "decision": "FLOOR_UNREACHABLE",
    "reason": "floor_unreachable:device cannot reach HYBRID",
    "s3_verdict": "FLOOR_UNREACHABLE",
    "cause_label": "loss_timeout",
    "security_reason": None,
    "crypto_status": "SKIPPED",
}

PHASE4_CRYPTO_ROUNDTRIP = {
    "trace_id": "trace_crypto_08",
    "ts": 1793526756939,
    "timestamp": "2026-11-01T09:52:36.939+00:00",
    "device_id": "device_002",
    "flow_id": "temperature_01",
    "sensitivity": "LOW",
    "minimum_mode": "CLASSICAL",
    "requested_mode": "PQC",
    "policy_version": 1,
    "authority_id": "QERIS-GATEWAY",
    "decision": "ALLOW",
    "reason": "Cryptographic session established and payload verified",
    "s3_verdict": "SUCCESS",
    "cause_label": "none",
    "security_reason": None,
    "crypto_status": "VERIFIED_ROUNDTRIP",
}

LEGACY_ALLOW = {
    "timestamp": "2026-10-22T10:05:19.162629",
    "flow_id": "emergency_stop",
    "requested_mode": "HYBRID",
    "decision": "ALLOW",
    "reason": "Policy satisfied",
}

LEGACY_REJECT = {
    "timestamp": "2026-10-22T10:05:19.162000",
    "flow_id": "emergency_stop",
    "requested_mode": "CLASSICAL",
    "decision": "REJECT",
    "reason": "Requested mode is below security floor",
}


class TestBridgePhase4Entries(unittest.TestCase):
    """Tests for current (Phase-4) gateway log entries."""

    def setUp(self):
        self.bridge = GatewayLogBridge()

    def test_allow_pqc_maps_to_success(self):
        r = self.bridge.convert_one(PHASE4_ALLOW)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.SUCCESS.value)
        self.assertEqual(r.mode, CryptoMode.PQC.value)
        self.assertEqual(r.sensitivity, SensitivityTier.LOW.value)
        self.assertEqual(r.cause_label, "none")
        self.assertEqual(r.device_id, "device_002")
        self.assertEqual(r.flow_id, "temperature_01")
        self.assertEqual(r.ts, 1793526756920)

    def test_reject_downgrade_maps_to_reject_security_failure(self):
        r = self.bridge.convert_one(PHASE4_REJECT_DOWNGRADE)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.REJECT.value)
        self.assertEqual(r.cause_label, "security_failure")
        self.assertEqual(r.sensitivity, SensitivityTier.CRITICAL.value)
        self.assertEqual(r.mode, CryptoMode.CLASSICAL.value)

    def test_floor_unreachable_maps_to_floor_unreachable_outcome(self):
        r = self.bridge.convert_one(PHASE4_FLOOR_UNREACHABLE)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.FLOOR_UNREACHABLE.value)
        self.assertEqual(r.cause_label, "loss_timeout")

    def test_crypto_roundtrip_maps_to_handshake_complete(self):
        r = self.bridge.convert_one(PHASE4_CRYPTO_ROUNDTRIP)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.SUCCESS.value)
        self.assertEqual(r.event, LogEvent.HANDSHAKE_COMPLETE.value)
        self.assertEqual(r.cause_label, "none")
        self.assertEqual(r.cause_injected, "none")

    def test_trace_id_embedded_in_run_id(self):
        r = self.bridge.convert_one(PHASE4_ALLOW)
        self.assertIn("trace_test_02", r.run_id)

    def test_cause_injected_always_none_for_live_logs(self):
        """Live gateway entries never have an injected fault."""
        for entry in (PHASE4_ALLOW, PHASE4_REJECT_DOWNGRADE, PHASE4_CRYPTO_ROUNDTRIP):
            r = self.bridge.convert_one(entry)
            self.assertEqual(r.cause_injected, "none")

    def test_baseline_defaults_to_full_gateway(self):
        r = self.bridge.convert_one(PHASE4_ALLOW)
        self.assertEqual(r.baseline, Baseline.FULL_GATEWAY.value)


class TestBridgeLegacyEntries(unittest.TestCase):
    """Tests for legacy (pre-Phase-4) gateway log entries."""

    def setUp(self):
        self.bridge = GatewayLogBridge()

    def test_legacy_allow_maps_to_success(self):
        r = self.bridge.convert_one(LEGACY_ALLOW)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.SUCCESS.value)
        self.assertEqual(r.device_id, "unknown")
        self.assertEqual(r.scenario, "legacy_entry")

    def test_legacy_reject_floor_infers_security_failure(self):
        r = self.bridge.convert_one(LEGACY_REJECT)
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, LogOutcome.REJECT.value)
        self.assertEqual(r.cause_label, "security_failure")

    def test_legacy_skip_mode(self):
        bridge = GatewayLogBridge(BridgeConfig(skip_legacy_entries=True))
        r = bridge.convert_one(LEGACY_ALLOW)
        self.assertIsNone(r)

    def test_legacy_timestamp_parsed(self):
        r = self.bridge.convert_one(LEGACY_ALLOW)
        self.assertIsNotNone(r)
        # ts should be a positive integer epoch-ms
        self.assertIsInstance(r.ts, int)
        self.assertGreater(r.ts, 0)


class TestBridgeCauseLabelInference(unittest.TestCase):
    """Tests for the legacy cause-label inference heuristic."""

    def test_signature_reason_is_security(self):
        self.assertEqual(_infer_cause_label_from_reason("bad signature", "REJECT"), "security_failure")

    def test_policy_reason_is_security(self):
        self.assertEqual(_infer_cause_label_from_reason("policy check failed", "REJECT"), "security_failure")

    def test_floor_reason_is_security(self):
        self.assertEqual(_infer_cause_label_from_reason("below security floor", "REJECT"), "security_failure")

    def test_downgrade_reason_is_security(self):
        self.assertEqual(_infer_cause_label_from_reason("downgrade attempt detected", "REJECT"), "security_failure")

    def test_mtu_reason_is_mtu_fragment(self):
        self.assertEqual(_infer_cause_label_from_reason("MTU exceeded, refragmenting", "REJECT"), "mtu_fragment")

    def test_timeout_reason_is_loss_timeout(self):
        self.assertEqual(_infer_cause_label_from_reason("no response timeout", "REJECT"), "loss_timeout")

    def test_allow_decision_is_none(self):
        self.assertEqual(_infer_cause_label_from_reason("Policy satisfied", "ALLOW"), "none")

    def test_unknown_reject_defaults_to_loss_timeout(self):
        self.assertEqual(_infer_cause_label_from_reason("something random happened", "REJECT"), "loss_timeout")


class TestBridgeFileIngestion(unittest.TestCase):
    """Tests for file-based ingestion of mixed log formats."""

    def test_ingest_mixed_file(self):
        entries = [
            PHASE4_ALLOW,
            PHASE4_REJECT_DOWNGRADE,
            PHASE4_CRYPTO_ROUNDTRIP,
            LEGACY_ALLOW,
            LEGACY_REJECT,
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
            tmp_path = f.name

        try:
            bridge = GatewayLogBridge()
            table = bridge.ingest_file(tmp_path)
            self.assertEqual(len(table), 5)
        finally:
            os.unlink(tmp_path)

    def test_ingest_phase4_only_file_with_skip_legacy(self):
        entries = [PHASE4_ALLOW, LEGACY_ALLOW, PHASE4_CRYPTO_ROUNDTRIP, LEGACY_REJECT]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
            tmp_path = f.name

        try:
            bridge = GatewayLogBridge(BridgeConfig(skip_legacy_entries=True))
            table = bridge.ingest_file(tmp_path)
            # Only Phase-4 entries (2) should be ingested
            self.assertEqual(len(table), 2)
            for r in table:
                self.assertNotEqual(r.scenario, "legacy_entry")
        finally:
            os.unlink(tmp_path)

    def test_ingest_actual_gateway_log(self):
        """Ingest the real gateway_logs.jsonl and verify all entries parse cleanly."""
        log_path = _REPO_ROOT / "qeris" / "s2" / "gateway_logs.jsonl"
        if not log_path.exists():
            self.skipTest("gateway_logs.jsonl not found")

        bridge = GatewayLogBridge()
        table = bridge.ingest_file(log_path)
        self.assertGreater(len(table), 0, "No records parsed from gateway_logs.jsonl")

        # Every record must have a valid outcome
        valid_outcomes = {o.value for o in LogOutcome}
        for r in table:
            self.assertIn(r.outcome, valid_outcomes, f"Invalid outcome: {r.outcome}")

    def test_missing_file_raises_file_not_found(self):
        bridge = GatewayLogBridge()
        with self.assertRaises(FileNotFoundError):
            bridge.ingest_file("/nonexistent/path/log.jsonl")

    def test_ingest_entries_list(self):
        bridge = GatewayLogBridge()
        entries = [PHASE4_ALLOW, PHASE4_REJECT_DOWNGRADE, PHASE4_FLOOR_UNREACHABLE]
        table = bridge.ingest_entries(entries)
        self.assertEqual(len(table), 3)

    def test_s4_analysis_compatibility(self):
        """Verify ingested records can be used with S4 analysis tools."""
        entries = [
            PHASE4_ALLOW,
            PHASE4_REJECT_DOWNGRADE,
            PHASE4_CRYPTO_ROUNDTRIP,
            PHASE4_FLOOR_UNREACHABLE,
        ]
        bridge = GatewayLogBridge()
        table = bridge.ingest_entries(entries)

        # Should not raise; evaluates classifier metrics on ingested table
        matrix = StatisticalAnalyzer.evaluate_classifier(table)
        self.assertIsNotNone(matrix)
        self.assertIsInstance(matrix.matrix, dict)

    def test_custom_config_propagated(self):
        cfg = BridgeConfig(
            run_id="my_run",
            baseline=Baseline.STATIC_PQC.value,
            device_class=DeviceClass.ESP32_CONSTRAINED.value,
        )
        bridge = GatewayLogBridge(cfg)
        r = bridge.convert_one(PHASE4_ALLOW)
        self.assertIn("my_run", r.run_id)
        self.assertEqual(r.baseline, Baseline.STATIC_PQC.value)
        self.assertEqual(r.device_class, DeviceClass.ESP32_CONSTRAINED.value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
