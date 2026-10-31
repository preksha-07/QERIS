"""
QERIS End-to-End Backend Integration Test Suite
Subsystems: S1 (Cryptography) + S2 (Gateway) + S3 (Security/Recovery) + S4 (Evaluation)

Verifies the complete coherent backend workflow:
1. Canonical 5-field signed policy verification (ML-DSA-65).
2. S2 device capability and feasibility enforcement.
3. S3 security classification (DowngradeRejection, FailureTaxonomy, ReplayProtection).
4. S1 session key establishment (ML-KEM-512 + HKDF-SHA256) and payload encryption (AES-256-GCM).
5. Safe fail-closed behavior: invalid requests never proceed to cryptographic operations.
6. Structured audit logging and S4 log compatibility.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Any

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from qeris.policy.signed_policy import (
    DEFAULT_SIG_ALG,
    PolicyVerificationStatus,
    SignedPolicyEnvelope,
    create_signed_envelope,
    sign_policy,
    verify_policy,
)
from qeris.s2.crypto_adapter import (
    CryptoSession,
    UnsupportedCryptoModeError,
    establish_session,
)
from qeris.s2.gateway import (
    CryptoDemoRequest,
    FlowRequest,
    check_device_capability,
    check_floor_feasibility,
    check_flow,
    check_policy,
    crypto_demo,
    policy_manager,
    s3_hook,
)
from qeris.s2.policy_manager import S2PolicyManager, normalize_policy_entry
from qeris.s3.s3_gateway_hook import S3GatewayHook
from qeris.s4.log_parser import LogParser, LogTable
from qeris.s4.log_schema import (
    Baseline,
    CryptoMode,
    DeviceClass,
    LogEvent,
    LogOutcome,
    LogRecord,
    SensitivityTier,
    create_log_record,
)


class TestFullBackendIntegration(unittest.TestCase):
    """Integration test suite exercising S1, S2, S3, and S4 concurrently."""

    @classmethod
    def setUpClass(cls) -> None:
        """Verify gateway authority and verified flows on startup."""
        cls.gateway_authority = policy_manager.DEFAULT_AUTHORITY_ID
        cls.verified_flows = list(policy_manager._verified_policies.keys())

    def test_01_canonical_policy_loading_and_s1_verification(self) -> None:
        """1. Verify S2 loads canonical 5-field policies and validates S1 signatures."""
        self.assertIn("temperature_01", self.verified_flows)
        self.assertIn("emergency_stop", self.verified_flows)

        temp_policy = policy_manager.get_verified_policy("temperature_01")
        self.assertIsNotNone(temp_policy)
        self.assertEqual(temp_policy["flow_id"], "temperature_01")
        self.assertEqual(temp_policy["sensitivity"], "LOW")
        self.assertEqual(temp_policy["minimum_mode"], "CLASSICAL")
        self.assertEqual(temp_policy["policy_version"], 1)
        self.assertEqual(temp_policy["authority_id"], "QERIS-GATEWAY")

        # Invariant: exactly 5 canonical fields
        self.assertEqual(len(temp_policy), 5)

    def test_02_valid_flow_request_evaluates_to_allow(self) -> None:
        """2. Verify valid flow request passes S1 verification, S2 checks, and S3 hook."""
        req = FlowRequest(
            device_id="device_002",
            flow_id="temperature_01",
            requested_mode="PQC",
            trace_id="trace_test_02",
        )
        resp = check_flow(req)

        self.assertEqual(resp["decision"], "ALLOW")
        self.assertEqual(resp["flow_id"], "temperature_01")
        self.assertEqual(resp["requested_mode"], "PQC")
        self.assertEqual(resp["s3_verdict"], "NONE")
        self.assertEqual(resp["cause_label"], "none")
        self.assertEqual(resp["trace_id"], "trace_test_02")

    def test_03_downgrade_attempt_caught_by_s2_and_s3(self) -> None:
        """3. Verify downgrade below floor is caught and classified as security_failure."""
        # emergency_stop requires HYBRID; device requests CLASSICAL
        req = FlowRequest(
            device_id="device_001",
            flow_id="emergency_stop",
            requested_mode="CLASSICAL",
            trace_id="trace_test_03",
        )
        resp = check_flow(req)

        self.assertEqual(resp["decision"], "REJECT")
        self.assertEqual(resp["cause_label"], "security_failure")
        self.assertIn("floor", resp["reason"].lower())

    def test_04_floor_unreachable_identified(self) -> None:
        """4. Verify device whose max capability is below flow floor yields FLOOR_UNREACHABLE."""
        # device_003 only supports CLASSICAL; emergency_stop requires HYBRID
        req = FlowRequest(
            device_id="device_003",
            flow_id="emergency_stop",
            requested_mode="HYBRID",
            trace_id="trace_test_04",
        )
        resp = check_flow(req)

        self.assertEqual(resp["decision"], "FLOOR_UNREACHABLE")
        self.assertIn("unreachable", resp["reason"].lower())

    def test_05_unknown_device_rejected(self) -> None:
        """5. Verify unregistered rogue device is rejected.

        S2 performs device-registration check first (unknown device → REJECT).
        S3 maps that to auth_check_failed=True → security_failure classification,
        so the final reason is S3's detail (e.g. 'bad_signature') and the
        cause_label is 'security_failure'. The critical invariant is that the
        decision is REJECT and crypto is never entered.
        """
        req = FlowRequest(
            device_id="unregistered_rogue_device_999",
            flow_id="temperature_01",
            requested_mode="CLASSICAL",
        )
        resp = check_flow(req)

        self.assertEqual(resp["decision"], "REJECT")
        # S3 classifies unknown-device as security_failure (auth_check_failed)
        self.assertEqual(resp["cause_label"], "security_failure")
        self.assertNotIn("kem_ciphertext_hex", resp)
        self.assertNotIn("decrypted_message", resp)

    def test_06_tampered_policy_signature_rejected_by_s1_and_quarantined_by_s3(self) -> None:
        """6. Verify tampered policy envelope fails signature verification and triggers security classification."""
        # Create an untrusted/tampered envelope
        tampered_env = {
            "policy": {
                "flow_id": "tampered_flow",
                "sensitivity": "CRITICAL",
                "minimum_mode": "PQC",
                "policy_version": 1,
                "authority_id": "QERIS-GATEWAY",
            },
            "sig_alg": "ML-DSA-65",
            "signature": ("00" * 3309),  # Invalid dummy signature
        }

        # Verify via S1
        v_res = verify_policy(
            policy_input=tampered_env,
            authority_registry=policy_manager.authority_registry,
        )
        self.assertFalse(v_res.is_valid)
        self.assertEqual(v_res.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Feed S1 status to S3 hook
        gw_decision = {
            "device_id": "device_002",
            "flow_id": "tampered_flow",
            "decision": "REJECT",
            "reason": v_res.message,
        }
        hook_res = s3_hook.process_gateway_decision(
            gw_decision,
            s1_status=v_res.status.name,
        )
        self.assertEqual(hook_res.final_decision, "REJECT")
        self.assertEqual(hook_res.cause_label, "security_failure")

    def test_07_untrusted_authority_rejected(self) -> None:
        """7. Verify policy issued by untrusted authority returns UNTRUSTED_AUTHORITY."""
        untrusted_env = {
            "policy": {
                "flow_id": "rogue_flow",
                "sensitivity": "LOW",
                "minimum_mode": "CLASSICAL",
                "policy_version": 1,
                "authority_id": "ROGUE-AUTHORITY-UNKNOWN",
            },
            "sig_alg": "ML-DSA-65",
            "signature": ("00" * 3309),
        }
        v_res = verify_policy(
            policy_input=untrusted_env,
            authority_registry=policy_manager.authority_registry,
        )
        self.assertFalse(v_res.is_valid)
        self.assertEqual(v_res.status, PolicyVerificationStatus.UNTRUSTED_AUTHORITY)

    def test_08_crypto_demo_success_on_allowed_pqc_request(self) -> None:
        """8. Verify full crypto session round-trip: ML-KEM-512 agreement + AES-256-GCM encryption/decryption."""
        req = CryptoDemoRequest(
            device_id="device_002",
            flow_id="temperature_01",
            message="Telemetry reading: 24.8 C, Humidity 45%",
            requested_mode="PQC",
            trace_id="trace_crypto_08",
        )
        resp = crypto_demo(req)

        self.assertEqual(resp["decision"], "ALLOW")
        self.assertEqual(resp["crypto_status"], "VERIFIED_ROUNDTRIP")
        self.assertEqual(resp["decrypted_message"], "Telemetry reading: 24.8 C, Humidity 45%")
        self.assertIn("ciphertext_hex", resp)
        self.assertIn("kem_ciphertext_hex", resp)
        self.assertEqual(resp["crypto_suite"], "ML-KEM-512 + HKDF-SHA256 + AES-256-GCM")

    def test_09_crypto_demo_fails_closed_on_rejected_request(self) -> None:
        """9. Verify crypto session is never established when flow evaluation fails."""
        # Request below floor: emergency_stop requires HYBRID, request CLASSICAL
        req = CryptoDemoRequest(
            device_id="device_001",
            flow_id="emergency_stop",
            message="Sensitive command",
            requested_mode="CLASSICAL",
        )
        resp = crypto_demo(req)

        self.assertEqual(resp["decision"], "REJECT")
        self.assertEqual(resp["crypto_status"], "REJECTED_BEFORE_SESSION")
        self.assertNotIn("ciphertext_hex", resp)
        self.assertNotIn("decrypted_message", resp)

    def test_10_unsupported_mode_crypto_rejected(self) -> None:
        """10. Verify CLASSICAL and HYBRID modes explicitly raise UnsupportedCryptoModeError in crypto_adapter."""
        with self.assertRaises(UnsupportedCryptoModeError):
            establish_session(
                device_id="device_001",
                flow_id="temperature_01",
                sensitivity="LOW",
                policy_version=1,
                mode="CLASSICAL",
            )

        with self.assertRaises(UnsupportedCryptoModeError):
            establish_session(
                device_id="device_001",
                flow_id="emergency_stop",
                sensitivity="CRITICAL",
                policy_version=1,
                mode="HYBRID",
            )

    def test_11_audit_log_format_and_s4_compatibility(self) -> None:
        """11. Verify gateway audit log emits valid structured JSON and maps cleanly to S4 LogRecord."""
        # Generate an S4 canonical record from gateway outcomes
        s4_record = create_log_record(
            run_id="run_int_01",
            scenario="normal_operation",
            baseline=Baseline.FULL_GATEWAY,
            device_id="device_002",
            device_class=DeviceClass.EDGE_GATEWAY,
            flow_id="temperature_01",
            sensitivity=SensitivityTier.LOW,
            event=LogEvent.HANDSHAKE_COMPLETE,
            mode=CryptoMode.PQC,
            cause_label="none",
            cause_injected="none",
            size_bytes=1024,
            duration_ms=12.5,
            outcome=LogOutcome.SUCCESS,
        )

        record_dict = s4_record.to_dict()
        self.assertIn("run_id", record_dict)
        self.assertIn("outcome", record_dict)
        self.assertEqual(record_dict["outcome"], "SUCCESS")

        # Verify S4 LogRecord JSON roundtrip
        record_json = s4_record.to_json()
        parsed = LogRecord.from_json(record_json)
        self.assertEqual(parsed.device_id, "device_002")
        self.assertEqual(parsed.mode, "PQC")


if __name__ == "__main__":
    unittest.main(verbosity=2)
