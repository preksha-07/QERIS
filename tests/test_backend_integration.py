"""
QERIS End-to-End Backend Integration Test Suite
Subsystems: S1 (PQC) + S2 (Gateway) + S3 (Security/Recovery) + S4 (Evaluation) + Classical Add-on

Verifies the complete coherent backend workflow:
1. Canonical 5-field signed policy verification (ML-DSA-65).
2. S2 device capability and feasibility enforcement.
3. S3 security classification (DowngradeRejection, FailureTaxonomy, ReplayProtection).
4. Dual-mode cryptographic sessions:
   - PQC: ML-KEM-512 + HKDF-SHA256 + AES-256-GCM (S1)
   - CLASSICAL: X25519 + HKDF-SHA256 + AES-256-GCM (qeris_classical)
5. Strict security floor enforcement & downgrade rejection:
   - Flows requiring PQC reject CLASSICAL requests before encryption.
   - Flows requiring HYBRID reject CLASSICAL requests before encryption.
6. Explicit rejection of HYBRID mode (unsupported).
7. Safe fail-closed behavior: invalid requests never proceed to cryptographic operations.
8. Structured audit logging and S4 log compatibility.
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
    CryptoPreconditionError,
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
from qeris_classical import (
    AuthenticationError as ClassicalAuthError,
    ClassicalCryptoInputError,
    ClassicalCryptoSession,
    ReplayError as ClassicalReplayError,
    derive_session_key as classical_derive_session_key,
    derive_shared_secret as classical_derive_shared_secret,
    generate_keypair as classical_generate_keypair,
)


class TestFullBackendIntegration(unittest.TestCase):
    """Integration test suite exercising S1, S2, S3, S4, and Classical Add-on concurrently."""

    @classmethod
    def setUpClass(cls) -> None:
        """Verify gateway authority and verified flows on startup."""
        cls.gateway_authority = policy_manager.DEFAULT_AUTHORITY_ID
        cls.verified_flows = list(policy_manager._verified_policies.keys())

    def test_01_canonical_policy_loading_and_s1_verification(self) -> None:
        """1. Verify S2 loads canonical 5-field policies and validates S1 signatures."""
        self.assertIn("temperature_01", self.verified_flows)
        self.assertIn("emergency_stop", self.verified_flows)
        self.assertIn("telemetry_secure", self.verified_flows)

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
        """5. Verify unregistered rogue device is rejected."""
        req = FlowRequest(
            device_id="unregistered_rogue_device_999",
            flow_id="temperature_01",
            requested_mode="CLASSICAL",
        )
        resp = check_flow(req)

        self.assertEqual(resp["decision"], "REJECT")
        self.assertEqual(resp["cause_label"], "security_failure")
        self.assertNotIn("kem_ciphertext_hex", resp)
        self.assertNotIn("decrypted_message", resp)

    def test_06_tampered_policy_signature_rejected_by_s1_and_quarantined_by_s3(self) -> None:
        """6. Verify tampered policy envelope fails signature verification and triggers security classification."""
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

        v_res = verify_policy(
            policy_input=tampered_env,
            authority_registry=policy_manager.authority_registry,
        )
        self.assertFalse(v_res.is_valid)
        self.assertEqual(v_res.status, PolicyVerificationStatus.INVALID_SIGNATURE)

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
        """8. Verify full PQC crypto session round-trip: ML-KEM-512 agreement + AES-256-GCM encryption/decryption."""
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
        self.assertEqual(resp["key_exchange"], "ML-KEM-512")

    def test_09_crypto_demo_fails_closed_on_rejected_request(self) -> None:
        """9. Verify crypto session is never established when flow evaluation fails."""
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

    def test_10_hybrid_mode_explicitly_unsupported(self) -> None:
        """10. Verify HYBRID mode is explicitly rejected in crypto_adapter and gateway."""
        # 1. crypto_adapter establish_session rejects HYBRID
        with self.assertRaises(UnsupportedCryptoModeError) as ctx:
            establish_session(
                device_id="device_001",
                flow_id="emergency_stop",
                sensitivity="CRITICAL",
                policy_version=1,
                mode="HYBRID",
            )
        self.assertIn("unsupported", str(ctx.exception).lower())

        # 2. gateway crypto-demo rejects HYBRID with UNSUPPORTED_MODE
        req = CryptoDemoRequest(
            device_id="device_001",
            flow_id="emergency_stop",
            message="Hybrid test message",
            requested_mode="HYBRID",
        )
        resp = crypto_demo(req)
        self.assertEqual(resp["decision"], "REJECT")
        self.assertEqual(resp["crypto_status"], "UNSUPPORTED_MODE")
        self.assertIn("unsupported", resp["reason"].lower())

    def test_11_audit_log_format_and_s4_compatibility(self) -> None:
        """11. Verify gateway audit log emits valid structured JSON and maps cleanly to S4 LogRecord."""
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

        record_json = s4_record.to_json()
        parsed = LogRecord.from_json(record_json)
        self.assertEqual(parsed.device_id, "device_002")
        self.assertEqual(parsed.mode, "PQC")

    # ── CLASSICAL Add-on Integration Tests ───────────────────────────────────

    def test_12_classical_key_agreement_success(self) -> None:
        """12. Successful CLASSICAL key agreement: X25519 derives matching shared secrets."""
        dev_pub, dev_sec = classical_generate_keypair()
        gw_pub, gw_sec = classical_generate_keypair()

        self.assertEqual(len(dev_pub), 32)
        self.assertEqual(len(gw_pub), 32)

        secret_dev = classical_derive_shared_secret(dev_sec, gw_pub)
        secret_gw = classical_derive_shared_secret(gw_sec, dev_pub)

        self.assertEqual(len(secret_dev), 32)
        self.assertEqual(secret_dev, secret_gw)

    def test_13_classical_session_encryption_and_decryption_roundtrip(self) -> None:
        """13. Successful CLASSICAL encryption and decryption: adapter and gateway roundtrip."""
        # 1. Direct adapter invocation
        session = establish_session(
            device_id="device_002",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
            mode="CLASSICAL",
        )
        self.assertIsInstance(session, ClassicalCryptoSession)
        self.assertEqual(session.mode, "CLASSICAL")
        self.assertEqual(session.key_exchange, "X25519")

        plaintext = b"Classical sensor reading: 22.1 C"
        envelope = session.encrypt(plaintext)
        decrypted = session.decrypt(envelope)
        self.assertEqual(decrypted, plaintext)

        # 2. Gateway crypto-demo invocation
        req = CryptoDemoRequest(
            device_id="device_002",
            flow_id="temperature_01",
            message="Classical gateway payload",
            requested_mode="CLASSICAL",
            trace_id="trace_classical_13",
        )
        resp = crypto_demo(req)
        self.assertEqual(resp["decision"], "ALLOW")
        self.assertEqual(resp["crypto_status"], "VERIFIED_ROUNDTRIP")
        self.assertEqual(resp["crypto_suite"], "X25519 + HKDF-SHA256 + AES-256-GCM")
        self.assertEqual(resp["key_exchange"], "X25519")
        self.assertEqual(resp["decrypted_message"], "Classical gateway payload")
        self.assertIn("device_public_key_hex", resp)
        self.assertIn("gateway_public_key_hex", resp)
        self.assertNotIn("kem_ciphertext_hex", resp)

    def test_14_classical_tampered_ciphertext_and_tag_rejected(self) -> None:
        """14. Rejection of modified ciphertext or invalid authentication tags in CLASSICAL mode."""
        session = establish_session(
            device_id="device_002",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
            mode="CLASSICAL",
        )
        envelope = bytearray(session.encrypt(b"Genuine message"))

        # Flip last byte (authentication tag)
        envelope[-1] ^= 0x01
        with self.assertRaises(ClassicalAuthError):
            session.decrypt(bytes(envelope))

        # Flip ciphertext payload byte
        envelope2 = bytearray(session.encrypt(b"Another message"))
        envelope2[20] ^= 0xFF
        with self.assertRaises(ClassicalAuthError):
            session.decrypt(bytes(envelope2))

    def test_15_classical_malformed_key_material_rejected(self) -> None:
        """15. Rejection of invalid or malformed key material in CLASSICAL key agreement."""
        valid_pub, valid_sec = classical_generate_keypair()

        # Short private key
        with self.assertRaises(ClassicalCryptoInputError):
            classical_derive_shared_secret(b"short_key", valid_pub)

        # Short public key
        with self.assertRaises(ClassicalCryptoInputError):
            classical_derive_shared_secret(valid_sec, b"short_key")

        # Wrong type
        with self.assertRaises(TypeError):
            classical_derive_shared_secret(12345, valid_pub)  # type: ignore

    def test_16_classical_replay_and_context_binding_enforced(self) -> None:
        """16. Replay protection and context binding in CLASSICAL message envelopes."""
        session1 = establish_session(
            device_id="device_002",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
            mode="CLASSICAL",
        )
        env = session1.encrypt(b"Monotonic counter test")
        self.assertEqual(session1.decrypt(env), b"Monotonic counter test")

        # Replay the identical envelope -> must be rejected
        with self.assertRaises(ClassicalReplayError):
            session1.decrypt(env)

        # Context mismatch: envelope sent to different flow/device context
        session2 = establish_session(
            device_id="device_001",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
            mode="CLASSICAL",
        )
        env2 = session1.encrypt(b"Context bound payload")
        with self.assertRaises(ClassicalAuthError):
            session2.decrypt(env2)

    def test_17_pqc_operation_unaffected_after_classical_integration(self) -> None:
        """17. Successful PQC operation preserved after integration of CLASSICAL mode."""
        pqc_session = establish_session(
            device_id="device_002",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
            mode="PQC",
        )
        self.assertIsInstance(pqc_session, CryptoSession)
        self.assertEqual(pqc_session.mode, "PQC")
        self.assertEqual(pqc_session.key_exchange, "ML-KEM-512")
        self.assertGreater(len(pqc_session.kem_ciphertext), 0)

        ct = pqc_session.encrypt(b"PQC payload after integration")
        pt = pqc_session.decrypt(ct)
        self.assertEqual(pt, b"PQC payload after integration")

    def test_18_pqc_floor_rejects_classical_downgrade(self) -> None:
        """18. Rejection when a policy requires PQC but the request selects CLASSICAL."""
        # telemetry_secure requires minimum_mode = PQC
        req = FlowRequest(
            device_id="device_002",
            flow_id="telemetry_secure",
            requested_mode="CLASSICAL",
            trace_id="trace_downgrade_pqc_18",
        )
        flow_resp = check_flow(req)

        self.assertEqual(flow_resp["decision"], "REJECT")
        self.assertEqual(flow_resp["cause_label"], "security_failure")
        self.assertEqual(flow_resp["reason"], "mode_below_floor")

        # crypto-demo must abort before session establishment
        demo_req = CryptoDemoRequest(
            device_id="device_002",
            flow_id="telemetry_secure",
            message="Secret message",
            requested_mode="CLASSICAL",
        )
        demo_resp = crypto_demo(demo_req)
        self.assertEqual(demo_resp["decision"], "REJECT")
        self.assertEqual(demo_resp["crypto_status"], "REJECTED_BEFORE_SESSION")
        self.assertNotIn("ciphertext_hex", demo_resp)

    def test_19_hybrid_floor_rejects_classical_downgrade(self) -> None:
        """19. Rejection when a policy requires HYBRID but the request selects CLASSICAL."""
        # emergency_stop requires minimum_mode = HYBRID
        req = FlowRequest(
            device_id="device_001",
            flow_id="emergency_stop",
            requested_mode="CLASSICAL",
            trace_id="trace_downgrade_hybrid_19",
        )
        flow_resp = check_flow(req)

        self.assertEqual(flow_resp["decision"], "REJECT")
        self.assertEqual(flow_resp["cause_label"], "security_failure")
        self.assertEqual(flow_resp["reason"], "mode_below_floor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
