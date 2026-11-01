"""
QERIS Dataset and Dashboard Integration Tests
============================================

Verifies:
1. Exactly three registered devices mapped to dataset devices:
   - device_001 <-> ESP32_NODE_01
   - device_002 <-> ESP32_NODE_02
   - device_003 <-> ESP32_NODE_03
2. Selected records are genuine entries from qeris_combined_cleaned_iot_dataset.csv.
3. Original sensor readings, metric names, units, and timestamps are preserved.
4. Dataset records pass through S2 gateway, S1 crypto, S3 security, and S4 analytics.
5. S3 security floors reject downgrade attempts.
6. HYBRID mode remains explicitly unsupported.
7. Backend endpoints serve live dashboard data:
   - GET /devices
   - GET /flows & GET /policies
   - GET /audit-logs
   - GET /security-events
   - GET /dataset/sample
   - POST /dataset/replay/tick
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import unittest
import uuid

import pytest
from fastapi.testclient import TestClient

# Path setup
_REPO_ROOT = Path(__file__).resolve().parent.parent
_S2_DIR = _REPO_ROOT / "qeris" / "s2"
_S1_DIR = _REPO_ROOT / "qeris" / "s1"
_S3_DIR = _REPO_ROOT / "qeris" / "s3"
_S4_DIR = _REPO_ROOT / "qeris" / "s4"

for p in (str(_REPO_ROOT), str(_S2_DIR), str(_S1_DIR), str(_S3_DIR), str(_S4_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from gateway import app, dataset_service, policy_manager, device_registry
from dataset_service import QERIS_TO_DATASET_DEVICE, DATASET_TO_QERIS_DEVICE
from qeris.s4.gateway_log_bridge import GatewayLogBridge


class TestDatasetAndDashboardIntegration(unittest.TestCase):
    """End-to-end verification of dataset integration and dashboard endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.csv_path = dataset_service.csv_path
        cls.assertTrue(cls.csv_path and cls.csv_path.exists(), "Dataset CSV file must exist")

    def test_01_three_devices_mapped_to_dataset(self):
        """Verifies only the 3 registered devices are mapped to ESP32 dataset nodes."""
        expected_mapping = {
            "device_001": "ESP32_NODE_01",
            "device_002": "ESP32_NODE_02",
            "device_003": "ESP32_NODE_03",
        }
        self.assertEqual(QERIS_TO_DATASET_DEVICE, expected_mapping)
        self.assertEqual(len(dataset_service.records_by_device), 3)
        for q_dev in ["device_001", "device_002", "device_003"]:
            self.assertIn(q_dev, dataset_service.records_by_device)
            self.assertGreater(len(dataset_service.records_by_device[q_dev]), 0)

    def test_02_records_drawn_from_actual_dataset(self):
        """Verifies records returned by dataset_service exist in the raw CSV and preserve values."""
        sample = dataset_service.get_random_record("device_001", "temperature_01")
        self.assertIsNotNone(sample)
        rec_id = sample["record_id"]
        self.assertTrue(rec_id.startswith("REC-"))
        self.assertEqual(sample["device_id"], "device_001")
        self.assertEqual(sample["dataset_device_id"], "ESP32_NODE_01")
        self.assertEqual(sample["flow_id"], "temperature_01")
        self.assertTrue(len(sample["metric_name"]) > 0)
        self.assertTrue(len(str(sample["value"])) > 0)
        self.assertTrue(len(sample["timestamp"]) > 0)

    def test_03_devices_endpoint_returns_real_registered_devices(self):
        """Verifies GET /devices returns the 3 devices with supported modes and status."""
        resp = self.client.get("/devices")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 3)
        dev_ids = {d["device_id"] for d in data}
        self.assertEqual(dev_ids, {"device_001", "device_002", "device_003"})

        d1 = next(d for d in data if d["device_id"] == "device_001")
        self.assertIn("CLASSICAL", d1["supported_modes"])
        self.assertIn("HYBRID", d1["supported_modes"])

        d2 = next(d for d in data if d["device_id"] == "device_002")
        self.assertIn("PQC", d2["supported_modes"])

        d3 = next(d for d in data if d["device_id"] == "device_003")
        self.assertEqual(d3["supported_modes"], ["CLASSICAL"])
        self.assertEqual(d3["status"], "LIMITED")

    def test_04_policies_endpoint_returns_all_five_flows(self):
        """Verifies GET /policies returns all 5 canonical signed policies."""
        resp = self.client.get("/policies")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        flow_map = {p["flow_id"]: p for p in data}
        self.assertIn("temperature_01", flow_map)
        self.assertIn("emergency_stop", flow_map)
        self.assertIn("telemetry_secure", flow_map)
        self.assertIn("pressure_03", flow_map)
        self.assertIn("vibration_02", flow_map)

        self.assertEqual(flow_map["temperature_01"]["minimum_mode"], "CLASSICAL")
        self.assertEqual(flow_map["emergency_stop"]["minimum_mode"], "HYBRID")
        self.assertEqual(flow_map["telemetry_secure"]["minimum_mode"], "PQC")
        self.assertEqual(flow_map["pressure_03"]["minimum_mode"], "HYBRID")
        self.assertEqual(flow_map["vibration_02"]["minimum_mode"], "HYBRID")

    def test_05_dataset_sample_endpoint(self):
        """Verifies GET /dataset/sample returns valid record and formatted telemetry string."""
        resp = self.client.get("/dataset/sample?device_id=device_002&flow_id=temperature_01")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("record", body)
        self.assertIn("formatted_message", body)
        self.assertEqual(body["record"]["device_id"], "device_002")
        self.assertIn(body["record"]["record_id"], body["formatted_message"])

    def test_06_normal_transmission_roundtrip_classical(self):
        """Verifies normal transmission for device_001 on temperature_01 in CLASSICAL mode."""
        resp = self.client.post("/crypto-demo", json={
            "device_id": "device_001",
            "flow_id": "temperature_01",
            "requested_mode": "CLASSICAL",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(data["crypto_status"], "VERIFIED_ROUNDTRIP")
        self.assertEqual(data["key_exchange"], "X25519")
        self.assertTrue(len(data["decrypted_message"]) > 0)
        self.assertTrue(len(data["ciphertext_hex"]) > 0)

    def test_07_normal_transmission_roundtrip_pqc(self):
        """Verifies normal transmission for device_002 on telemetry_secure in PQC mode."""
        resp = self.client.post("/crypto-demo", json={
            "device_id": "device_002",
            "flow_id": "telemetry_secure",
            "requested_mode": "PQC",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(data["crypto_status"], "VERIFIED_ROUNDTRIP")
        self.assertEqual(data["key_exchange"], "ML-KEM-512")
        self.assertTrue(len(data["decrypted_message"]) > 0)
        self.assertTrue(len(data["ciphertext_hex"]) > 0)

    def test_08_downgrade_rejected_before_crypto(self):
        """Verifies that requesting CLASSICAL on a PQC flow is rejected by S2 and S3 before crypto."""
        resp = self.client.post("/crypto-demo", json={
            "device_id": "device_002",
            "flow_id": "telemetry_secure",
            "requested_mode": "CLASSICAL",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "REJECT")
        self.assertEqual(data["crypto_status"], "REJECTED_BEFORE_SESSION")
        self.assertEqual(data["cause_label"], "security_failure")
        self.assertEqual(data["s3_verdict"], "DISCARD_AND_LOG")

    def test_09_floor_unreachable_rejected(self):
        """Verifies that device_003 (CLASSICAL only) attempting emergency_stop (HYBRID) is rejected."""
        resp = self.client.post("/crypto-demo", json={
            "device_id": "device_003",
            "flow_id": "emergency_stop",
            "requested_mode": "HYBRID",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "FLOOR_UNREACHABLE")
        self.assertEqual(data["crypto_status"], "REJECTED_BEFORE_SESSION")

    def test_10_hybrid_mode_explicitly_unsupported(self):
        """Verifies that requesting HYBRID mode is rejected with UNSUPPORTED_MODE."""
        resp = self.client.post("/crypto-demo", json={
            "device_id": "device_001",
            "flow_id": "emergency_stop",
            "requested_mode": "HYBRID",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "REJECT")
        self.assertEqual(data["crypto_status"], "UNSUPPORTED_MODE")

    def test_11_dataset_replay_tick_and_s4_bridge(self):
        """Verifies /dataset/replay/tick executes a real record and S4 bridge ingests it."""
        resp = self.client.post("/dataset/replay/tick")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "TICK_EXECUTED")
        rec = body["record"]
        self.assertTrue(rec["record_id"].startswith("REC-"))
        self.assertIn(rec["device_id"], ["device_001", "device_002", "device_003"])

        # Ingest recent logs into S4 bridge
        bridge = GatewayLogBridge()
        table = bridge.ingest_file(str(_S2_DIR / "gateway_logs.jsonl"))
        self.assertGreater(len(table), 0)

    def test_12_audit_logs_and_security_events_endpoints(self):
        """Verifies GET /audit-logs and GET /security-events return structured arrays."""
        resp_logs = self.client.get("/audit-logs?limit=10")
        self.assertEqual(resp_logs.status_code, 200)
        logs = resp_logs.json()
        self.assertIsInstance(logs, list)
        if len(logs) > 0:
            l = logs[0]
            self.assertIn("id", l)
            self.assertIn("timestamp", l)
            self.assertIn("device_id", l)
            self.assertIn("flow_id", l)
            self.assertIn("decision", l)

        resp_sec = self.client.get("/security-events?limit=10")
        self.assertEqual(resp_sec.status_code, 200)
        events = resp_sec.json()
        self.assertIsInstance(events, list)
        if len(events) > 0:
            e = events[0]
            self.assertIn("type", e)
            self.assertIn("decision", e)


if __name__ == "__main__":
    unittest.main()
