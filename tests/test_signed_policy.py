"""
QERIS Signed Policy Unit Tests
Milestone: Demo 1 — Standalone Signed-Policy Proof of Concept
Author: S1 (Cryptography and Device Engineer)

Scope & Viva Notes:
- Standard-library unittest suite validating standalone signed-policy operations.
- Uses real liboqs-python calls with algorithm ML-DSA-65 for cryptographic tests.
- Comprehensive test coverage including Step 2B.1 targeted hardening:
  1. ML-DSA-65 availability in the installed library.
  2. Valid policy signature accepted with the correct TEST ONLY public key.
  3. Policy alteration rejected.
  4. Signature alteration rejected.
  5. Verification with a different valid TEST ONLY public key rejected.
  6. WRONG_ALGORITHM returned for a mismatched sig_alg.
  6b. Supplementary control-flow test: crypto verifier is not instantiated on wrong algorithm.
  7. Unsupported signing algorithm rejected.
  8. Missing required fields rejected.
  9. Malformed serialized input rejected.
 10. Invalid policy field types and invalid last_seen_version types rejected.
 11. Lower version rejected as STALE_POLICY on authentic policy.
 12. Equal-version behavior matches documented rule.
 13. Deterministic serialization for equivalent mappings with different key insertion orders.
 14. Nested supported mappings serialize deterministically.
 15. Unsupported JSON values fail clearly.
 16. Any changed security-relevant field cannot pass signature verification.
 17. Forged lower-version policy rejected with INVALID_SIGNATURE (never STALE_POLICY).
 18. Strict JSON deserialization rejects duplicate keys.
 19. Strict JSON deserialization rejects non-standard constants (NaN, Infinity, -Infinity).
 20. Safe timestamp validation prevents OverflowError on huge integers.
 21. Unpaired Unicode surrogates fail cleanly during UTF-8 serialization.
 22. Allowed-algorithms configuration type and content validation.
 23. Authentic higher-version policy accepted as VALID.
 24. Caller stored version state cannot be advanced on verification failure.
 25. Truncated or empty signatures, keys, and policy inputs fail closed.
 26. Native oqs.Signature instances freed on both success and failure.
- Security constraints:
  - Ephemeral TEST ONLY keys; never production keys.
  - Never logs or prints private keys or secret material.
"""

from collections.abc import Mapping
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from typing import Any

# Ensure repository root is on sys.path for direct invocation
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import oqs
from qeris.policy.serialization import (
    PROVISIONAL_CANDIDATE_FIELDS,
    deserialize_policy_from_bytes,
    serialize_policy_to_bytes,
)
from qeris.policy.signed_policy import (
    DEFAULT_SIG_ALG,
    MAX_EXPIRY_TIMESTAMP,
    PolicyValidationError,
    PolicyVerificationResult,
    PolicyVerificationStatus,
    sign_policy,
    validate_allowed_algorithms,
    validate_policy_structure,
    verify_policy,
)


def create_baseline_test_policy(**overrides: Any) -> dict[str, Any]:
    """
    Helper to construct a baseline provisional policy for test fixtures.
    Labeled: TEST ONLY.
    """
    policy = {
        "version": 1,
        "sig_alg": "ML-DSA-65",
        "flow_to_tier": {"LOW": "LOW"},
        "tier_to_suite": {"LOW": "ML-KEM-512-AES-128-GCM"},
        "expiry": 1893456000,  # Provisional timestamp (enforcement unresolved)
        "revocation_list": [],  # Provisional revocation list (semantics unresolved)
    }
    policy.update(overrides)
    return policy


class TestSignedPolicy(unittest.TestCase):
    """Test suite for the standalone signed-policy module using real liboqs ML-DSA-65."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate an ephemeral TEST ONLY issuer keypair for test execution."""
        cls.test_issuer_sig = oqs.Signature(DEFAULT_SIG_ALG)
        # TEST ONLY ephemeral issuer keypair (never used in production)
        cls.test_issuer_public_key = cls.test_issuer_sig.generate_keypair()

    @classmethod
    def tearDownClass(cls) -> None:
        """Release native C memory for the test issuer signature object."""
        if hasattr(cls, "test_issuer_sig") and cls.test_issuer_sig is not None:
            cls.test_issuer_sig.free()

    def test_01_ml_dsa_65_enabled_in_library(self) -> None:
        """1. Verify ML-DSA-65 is enabled in the installed liboqs environment."""
        enabled = oqs.get_enabled_sig_mechanisms()
        self.assertIn(
            "ML-DSA-65",
            enabled,
            "ML-DSA-65 must be enabled in the active liboqs installation.",
        )

    def test_02_valid_policy_signed_with_test_key_verifies(self) -> None:
        """2. Verify a valid policy signed with a TEST ONLY key verifies with matching public key."""
        policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Verification via policy dictionary input
        result_from_dict = verify_policy(
            policy_input=policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertTrue(result_from_dict.is_valid)
        self.assertEqual(result_from_dict.status, PolicyVerificationStatus.VALID)

        # Verification via raw signed bytes input
        result_from_bytes = verify_policy(
            policy_input=signed_bytes,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertTrue(result_from_bytes.is_valid)
        self.assertEqual(result_from_bytes.status, PolicyVerificationStatus.VALID)

    def test_03_changed_policy_fails_verification(self) -> None:
        """3. Verify a changed policy payload fails signature verification."""
        policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Tamper with policy data (e.g. elevate version)
        tampered_policy = create_baseline_test_policy(version=2)
        result = verify_policy(
            policy_input=tampered_policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Tamper with serialized bytes where JSON remains syntactically valid
        tampered_bytes = signed_bytes.replace(b'"version":1', b'"version":2')
        result_bytes = verify_policy(
            policy_input=tampered_bytes,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result_bytes.is_valid)
        self.assertEqual(result_bytes.status, PolicyVerificationStatus.INVALID_SIGNATURE)

    def test_04_modified_signature_fails_verification(self) -> None:
        """4. Verify a modified signature fails verification."""
        policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Flip one bit in the signature
        tampered_signature = bytearray(signature)
        tampered_signature[0] ^= 0x01

        result = verify_policy(
            policy_input=policy,
            signature=bytes(tampered_signature),
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)

    def test_05_different_valid_public_key_rejected(self) -> None:
        """5. Verify verification with a different valid TEST ONLY public key is rejected."""
        policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Generate a separate, distinct valid keypair (Keypair B)
        other_sig = None
        try:
            other_sig = oqs.Signature(DEFAULT_SIG_ALG)
            other_public_key = other_sig.generate_keypair()

            result = verify_policy(
                policy_input=policy,
                signature=signature,
                issuer_public_key=other_public_key,
            )
            self.assertFalse(result.is_valid)
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)
        finally:
            if other_sig is not None:
                other_sig.free()

    def test_06_wrong_sig_alg_rejected_before_crypto_verification(self) -> None:
        """6. Verify a wrong sig_alg is rejected with WRONG_ALGORITHM before crypto verification."""
        policy = create_baseline_test_policy(sig_alg="ML-DSA-44")
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        result = verify_policy(
            policy_input=policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
            allowed_algorithms=("ML-DSA-65",),
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.WRONG_ALGORITHM)
        self.assertEqual(result.status, "WRONG_ALGORITHM")

    def test_06b_wrong_sig_alg_skips_cryptographic_verification_call(self) -> None:
        """6b. Supplementary control-flow test: verifies oqs.Signature is not instantiated
        when sig_alg is not in the allowed algorithms list."""
        policy = create_baseline_test_policy(sig_alg="ML-DSA-44")
        calls = []
        real_sig_init = oqs.Signature.__init__

        def spy_init(self_obj, *args, **kwargs):
            calls.append(args)
            return real_sig_init(self_obj, *args, **kwargs)

        with patch.object(oqs.Signature, "__init__", side_effect=spy_init):
            result = verify_policy(
                policy_input=policy,
                signature=b"\x00" * 3309,
                issuer_public_key=b"\x00" * 1952,
                allowed_algorithms=("ML-DSA-65",),
            )

        self.assertEqual(result.status, PolicyVerificationStatus.WRONG_ALGORITHM)
        self.assertEqual(len(calls), 0, "oqs.Signature must not be instantiated when algorithm is disallowed.")

    def test_07_unsupported_signing_algorithm_rejected(self) -> None:
        """7. Verify an unsupported signing algorithm is rejected."""
        policy = create_baseline_test_policy(sig_alg="NONEXISTENT-PQC-SIG-999")
        dummy_sig = b"\x00" * 64
        dummy_pk = b"\x00" * 64

        result = verify_policy(
            policy_input=policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
            allowed_algorithms=("NONEXISTENT-PQC-SIG-999",),
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.UNSUPPORTED_ALGORITHM)

    def test_08_missing_required_fields_rejected(self) -> None:
        """8. Verify missing required fields are rejected with INVALID_STRUCTURE."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        for field in PROVISIONAL_CANDIDATE_FIELDS:
            policy = create_baseline_test_policy()
            del policy[field]
            result = verify_policy(
                policy_input=policy,
                signature=dummy_sig,
                issuer_public_key=dummy_pk,
            )
            self.assertFalse(result.is_valid)
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_09_malformed_serialized_input_rejected(self) -> None:
        """9. Verify malformed serialized input (invalid UTF-8, truncated JSON, non-object JSON) is rejected."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        malformed_cases = [
            b"this-is-not-valid-json",
            b'{"version": 1, "sig_alg":',  # truncated JSON
            b"[1, 2, 3]",                  # JSON list instead of object
            b"\xff\xfe\x00\x00",           # invalid UTF-8
            b'"just-a-string"',            # JSON string instead of object
        ]
        for bad_bytes in malformed_cases:
            result = verify_policy(
                policy_input=bad_bytes,
                signature=dummy_sig,
                issuer_public_key=dummy_pk,
            )
            self.assertFalse(result.is_valid)
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_10_invalid_field_types_and_last_seen_version_rejected(self) -> None:
        """10. Verify invalid policy field types and invalid last_seen_version types are rejected."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        # 10a. Field type rejections in policy
        invalid_type_cases = [
            ("version", True),   # boolean instead of int
            ("version", "1"),    # string instead of int
            ("version", 1.5),    # float instead of int
            ("version", 0),      # non-positive int
            ("version", -1),     # negative int
            ("sig_alg", 123),    # int instead of str
            ("sig_alg", "   "),  # whitespace-only str
            ("flow_to_tier", ["not", "a", "dict"]),
            ("flow_to_tier", {1: "LOW"}),          # non-string key
            ("flow_to_tier", {"LOW": 123}),        # non-string value
            ("tier_to_suite", "not-a-dict"),
            ("tier_to_suite", {"LOW": 999}),       # non-string value
            ("expiry", "not-a-timestamp"),
            ("expiry", True),                      # bool instead of numeric
            ("expiry", float("nan")),              # NaN
            ("expiry", float("inf")),              # Infinity
            ("expiry", -5),                        # negative timestamp
            ("revocation_list", "not-a-list"),
            ("revocation_list", [123]),            # non-string item in list
        ]
        for field, invalid_val in invalid_type_cases:
            policy = create_baseline_test_policy()
            policy[field] = invalid_val
            result = verify_policy(
                policy_input=policy,
                signature=dummy_sig,
                issuer_public_key=dummy_pk,
            )
            self.assertFalse(result.is_valid, f"Expected failure for {field}={invalid_val!r}")
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

        # 10b. Invalid last_seen_version argument types raise TypeError
        valid_policy = create_baseline_test_policy()
        invalid_last_seen_cases = ["1", True, 1.5, -1]
        for bad_lsv in invalid_last_seen_cases:
            with self.assertRaises(TypeError):
                verify_policy(
                    policy_input=valid_policy,
                    signature=dummy_sig,
                    issuer_public_key=dummy_pk,
                    last_seen_version=bad_lsv,
                )

        # 10c. Invalid allow_equal_version type raises TypeError
        with self.assertRaises(TypeError):
            verify_policy(
                policy_input=valid_policy,
                signature=dummy_sig,
                issuer_public_key=dummy_pk,
                allow_equal_version="not-a-bool",  # type: ignore
            )

    def test_11_policy_version_lower_than_last_seen_rejected_stale_policy(self) -> None:
        """11. Verify policy version lower than last_seen_version is rejected with STALE_POLICY on authentic policy."""
        policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        result = verify_policy(
            policy_input=policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=2,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.STALE_POLICY)
        self.assertEqual(result.status, "STALE_POLICY")

    def test_12_policy_version_equal_to_last_seen_handled(self) -> None:
        """12. Verify policy version equal to last_seen_version is handled per documented rule."""
        policy = create_baseline_test_policy(version=2)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Default rule: equal version is allowed (idempotent re-announcement)
        result_allowed = verify_policy(
            policy_input=policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=2,
            allow_equal_version=True,
        )
        self.assertTrue(result_allowed.is_valid)
        self.assertEqual(result_allowed.status, PolicyVerificationStatus.VALID)

        # Strict monotonic rule: equal version rejected with STALE_POLICY
        result_strict = verify_policy(
            policy_input=policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=2,
            allow_equal_version=False,
        )
        self.assertFalse(result_strict.is_valid)
        self.assertEqual(result_strict.status, PolicyVerificationStatus.STALE_POLICY)

    def test_13_serialization_is_deterministic(self) -> None:
        """13. Verify provisional serialization produces deterministic bytes regardless of key insertion order."""
        dict1 = {
            "version": 1,
            "sig_alg": "ML-DSA-65",
            "flow_to_tier": {"LOW": "LOW"},
            "tier_to_suite": {"LOW": "ML-KEM-512-AES-128-GCM"},
            "expiry": 1893456000,
            "revocation_list": [],
        }
        dict2 = {
            "revocation_list": [],
            "expiry": 1893456000,
            "tier_to_suite": {"LOW": "ML-KEM-512-AES-128-GCM"},
            "flow_to_tier": {"LOW": "LOW"},
            "sig_alg": "ML-DSA-65",
            "version": 1,
        }
        bytes1 = serialize_policy_to_bytes(dict1)
        bytes2 = serialize_policy_to_bytes(dict2)
        self.assertEqual(bytes1, bytes2)

        # Deserialization roundtrip
        roundtrip = deserialize_policy_from_bytes(bytes1)
        self.assertEqual(roundtrip, dict1)

    def test_14_nested_supported_mappings_serialize_deterministically(self) -> None:
        """14. Verify nested mappings serialize deterministically regardless of internal key insertion order."""
        policy_a = {
            "version": 1,
            "sig_alg": "ML-DSA-65",
            "flow_to_tier": {"FLOW_A": "LOW", "FLOW_B": "HIGH"},
            "tier_to_suite": {"HIGH": "SUITE_PQC_HIGH", "LOW": "SUITE_PQC_LOW"},
            "expiry": 1893456000,
            "revocation_list": ["DEV_001", "DEV_002"],
        }
        policy_b = {
            "version": 1,
            "sig_alg": "ML-DSA-65",
            "flow_to_tier": {"FLOW_B": "HIGH", "FLOW_A": "LOW"},
            "tier_to_suite": {"LOW": "SUITE_PQC_LOW", "HIGH": "SUITE_PQC_HIGH"},
            "expiry": 1893456000,
            "revocation_list": ["DEV_001", "DEV_002"],
        }
        bytes_a = serialize_policy_to_bytes(policy_a)
        bytes_b = serialize_policy_to_bytes(policy_b)
        self.assertEqual(bytes_a, bytes_b)

    def test_15_unsupported_json_values_fail_clearly(self) -> None:
        """15. Verify unsupported JSON values (sets, NaN, non-serializable objects) fail clearly."""
        # Non-serializable set
        policy_with_set = create_baseline_test_policy(flow_to_tier={"LOW": {"set_item"}})
        with self.assertRaises(ValueError):
            serialize_policy_to_bytes(policy_with_set)

        # Non-serializable NaN float
        policy_with_nan = create_baseline_test_policy(expiry=float("nan"))
        with self.assertRaises(ValueError):
            serialize_policy_to_bytes(policy_with_nan)

        # Rejection during verify_policy with non-serializable mapping
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952
        result = verify_policy(
            policy_input=policy_with_set,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_16_each_security_relevant_field_modification_fails_verification(self) -> None:
        """16. Verify that modifying any individual security-relevant field causes verification failure."""
        baseline_policy = create_baseline_test_policy(version=1)
        signed_bytes, signature = sign_policy(baseline_policy, self.test_issuer_sig)

        tamper_variations = [
            ("version", 2),
            ("flow_to_tier", {"LOW": "MODIFIED_TIER"}),
            ("tier_to_suite", {"LOW": "MODIFIED_SUITE"}),
            ("expiry", 1999999999),
            ("revocation_list", ["REVOKED_DEVICE_01"]),
            ("sig_alg", "ML-DSA-87"),
        ]

        for field_name, altered_val in tamper_variations:
            mutated_policy = create_baseline_test_policy()
            mutated_policy[field_name] = altered_val

            allowed = ("ML-DSA-65", "ML-DSA-87") if field_name == "sig_alg" else ("ML-DSA-65",)
            result = verify_policy(
                policy_input=mutated_policy,
                signature=signature,
                issuer_public_key=self.test_issuer_public_key,
                allowed_algorithms=allowed,
            )
            self.assertFalse(
                result.is_valid,
                f"Modifying security-relevant field '{field_name}' must fail verification.",
            )
            self.assertIn(
                result.status,
                (PolicyVerificationStatus.INVALID_SIGNATURE, PolicyVerificationStatus.WRONG_ALGORITHM),
            )

    def test_17_forged_lower_version_policy_rejected_as_invalid_signature_not_stale(self) -> None:
        """17. Prove that a forged lower-version policy fails with INVALID_SIGNATURE, not STALE_POLICY.
        (Authenticates origin strictly before evaluating anti-rollback version logic)."""
        # Lower-version policy with forged signature
        forged_policy = create_baseline_test_policy(version=1)
        forged_signature = b"\x00" * 3309  # Invalid dummy signature

        # Evaluated against a higher last_seen_version (e.g. 2)
        result = verify_policy(
            policy_input=forged_policy,
            signature=forged_signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=2,
        )

        # Must reject as INVALID_SIGNATURE, proving it is never evaluated as an authentic stale policy
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)
        self.assertNotEqual(result.status, PolicyVerificationStatus.STALE_POLICY)

    def test_18_strict_json_rejects_duplicate_keys(self) -> None:
        """18. Strict JSON deserialization rejects duplicate keys in both top-level and nested objects."""
        # Top-level duplicate key
        top_dup = b'{"version":1,"sig_alg":"ML-DSA-65","version":2,"flow_to_tier":{"LOW":"LOW"},"tier_to_suite":{"LOW":"ML-KEM-512-AES-128-GCM"},"expiry":1893456000,"revocation_list":[]}'
        with self.assertRaises(ValueError) as ctx:
            deserialize_policy_from_bytes(top_dup)
        self.assertIn("Duplicate key", str(ctx.exception))

        # Nested duplicate key in flow_to_tier
        nested_dup = b'{"version":1,"sig_alg":"ML-DSA-65","flow_to_tier":{"LOW":"LOW","LOW":"HIGH"},"tier_to_suite":{"LOW":"ML-KEM-512-AES-128-GCM"},"expiry":1893456000,"revocation_list":[]}'
        with self.assertRaises(ValueError) as ctx:
            deserialize_policy_from_bytes(nested_dup)
        self.assertIn("Duplicate key", str(ctx.exception))

        # Rejection through verify_policy returns INVALID_STRUCTURE
        result = verify_policy(
            policy_input=top_dup,
            signature=b"\x00" * 3309,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_19_strict_json_rejects_non_standard_constants(self) -> None:
        """19. Strict JSON deserialization rejects non-standard constants (NaN, Infinity, -Infinity)."""
        nan_payload = b'{"version":1,"sig_alg":"ML-DSA-65","flow_to_tier":{"LOW":"LOW"},"tier_to_suite":{"LOW":"ML-KEM-512-AES-128-GCM"},"expiry":NaN,"revocation_list":[]}'
        inf_payload = b'{"version":1,"sig_alg":"ML-DSA-65","flow_to_tier":{"LOW":"LOW"},"tier_to_suite":{"LOW":"ML-KEM-512-AES-128-GCM"},"expiry":Infinity,"revocation_list":[]}'
        neginf_payload = b'{"version":1,"sig_alg":"ML-DSA-65","flow_to_tier":{"LOW":"LOW"},"tier_to_suite":{"LOW":"ML-KEM-512-AES-128-GCM"},"expiry":-Infinity,"revocation_list":[]}'

        for payload in [nan_payload, inf_payload, neginf_payload]:
            with self.assertRaises(ValueError) as ctx:
                deserialize_policy_from_bytes(payload)
            self.assertIn("Non-standard JSON constant rejected", str(ctx.exception))

            result = verify_policy(
                policy_input=payload,
                signature=b"\x00" * 3309,
                issuer_public_key=self.test_issuer_public_key,
            )
            self.assertFalse(result.is_valid)
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_20_safe_timestamp_validation_prevents_overflow_error(self) -> None:
        """20. Safe timestamp validation handles huge integer timestamps without uncaught OverflowError."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        # 10**1000 would cause OverflowError if converted to float in math.isnan
        huge_int_policy = create_baseline_test_policy(expiry=10**1000)

        # Direct structural validation: no OverflowError, returns INVALID_STRUCTURE
        status, msg = validate_policy_structure(huge_int_policy, raise_exception=False)
        self.assertEqual(status, PolicyVerificationStatus.INVALID_STRUCTURE)
        self.assertIn("out of range", msg)

        # verify_policy handles it cleanly without crashing
        result = verify_policy(
            policy_input=huge_int_policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

        # Exceeding MAX_EXPIRY_TIMESTAMP boundary
        over_max_policy = create_baseline_test_policy(expiry=MAX_EXPIRY_TIMESTAMP + 1)
        result_over = verify_policy(
            policy_input=over_max_policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
        )
        self.assertFalse(result_over.is_valid)
        self.assertEqual(result_over.status, PolicyVerificationStatus.INVALID_STRUCTURE)

        # Exactly at MAX_EXPIRY_TIMESTAMP: valid integer timestamp
        at_max_policy = create_baseline_test_policy(expiry=MAX_EXPIRY_TIMESTAMP)
        status_max, _ = validate_policy_structure(at_max_policy, raise_exception=False)
        self.assertEqual(status_max, PolicyVerificationStatus.VALID)

    def test_21_unpaired_unicode_surrogate_fails_cleanly(self) -> None:
        """21. Unpaired Unicode surrogates fail cleanly during UTF-8 serialization and validation."""
        surrogate_policy = create_baseline_test_policy(sig_alg="ML-DSA-65\ud800")

        # Direct serialize_policy_to_bytes raises ValueError (not raw UnicodeEncodeError)
        with self.assertRaises(ValueError) as ctx:
            serialize_policy_to_bytes(surrogate_policy)
        self.assertIn("serialization failed", str(ctx.exception).lower())

        # Structural validation rejects it cleanly
        status, msg = validate_policy_structure(surrogate_policy, raise_exception=False)
        self.assertEqual(status, PolicyVerificationStatus.INVALID_STRUCTURE)
        self.assertIn("surrogate", msg.lower())

        # verify_policy rejects it cleanly
        result = verify_policy(
            policy_input=surrogate_policy,
            signature=b"\x00" * 3309,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_22_allowed_algorithms_argument_validation(self) -> None:
        """22. Allowed-algorithms configuration type and content validation."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952
        policy = create_baseline_test_policy()

        # Reject str (prevents substring matching like 'M' in 'ML-DSA-65')
        with self.assertRaises(TypeError):
            validate_allowed_algorithms("ML-DSA-65")
        with self.assertRaises(TypeError):
            verify_policy(policy, dummy_sig, dummy_pk, allowed_algorithms="ML-DSA-65")  # type: ignore

        # Reject bytes
        with self.assertRaises(TypeError):
            validate_allowed_algorithms(b"ML-DSA-65")

        # Reject non-collection
        with self.assertRaises(TypeError):
            validate_allowed_algorithms(12345)

        # Reject collection containing non-strings
        with self.assertRaises(TypeError):
            validate_allowed_algorithms(["ML-DSA-65", 123])

        # Reject empty or whitespace-only algorithm strings
        with self.assertRaises(ValueError):
            validate_allowed_algorithms([""])
        with self.assertRaises(ValueError):
            validate_allowed_algorithms(["ML-DSA-65", "   "])

        # Accept valid permitted collection types: tuple, list, set, frozenset
        self.assertEqual(validate_allowed_algorithms(("ML-DSA-65",)), frozenset({"ML-DSA-65"}))
        self.assertEqual(validate_allowed_algorithms(["ML-DSA-65"]), frozenset({"ML-DSA-65"}))
        self.assertEqual(validate_allowed_algorithms({"ML-DSA-65"}), frozenset({"ML-DSA-65"}))
        self.assertEqual(validate_allowed_algorithms(frozenset({"ML-DSA-65"})), frozenset({"ML-DSA-65"}))

    def test_23_authentic_higher_version_accepted(self) -> None:
        """23. Verify an authentic policy with version > last_seen_version is accepted as VALID."""
        policy = create_baseline_test_policy(version=3)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        result = verify_policy(
            policy_input=policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=2,
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.VALID)

    def test_24_caller_version_state_not_advanced_on_failed_verification(self) -> None:
        """24. Verify failed verification (forgery or stale) cannot authorize updating stored version."""
        # Gateway caller maintains local version state
        gateway_stored_version = 2

        # Case A: Attacker presents forged policy claiming version 10
        forged_policy = create_baseline_test_policy(version=10)
        forged_signature = b"\x00" * 3309
        result_forged = verify_policy(
            policy_input=forged_policy,
            signature=forged_signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=gateway_stored_version,
        )
        self.assertFalse(result_forged.is_valid)
        if result_forged.is_valid:
            gateway_stored_version = forged_policy["version"]
        self.assertEqual(gateway_stored_version, 2, "Stored version must not advance on forged policy.")

        # Case B: Replay of authentic stale policy (version 1)
        stale_policy = create_baseline_test_policy(version=1)
        _, stale_sig = sign_policy(stale_policy, self.test_issuer_sig)
        result_stale = verify_policy(
            policy_input=stale_policy,
            signature=stale_sig,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=gateway_stored_version,
        )
        self.assertFalse(result_stale.is_valid)
        if result_stale.is_valid:
            gateway_stored_version = stale_policy["version"]
        self.assertEqual(gateway_stored_version, 2, "Stored version must not update on stale policy.")

    def test_25_truncated_or_empty_crypto_inputs_rejected(self) -> None:
        """25. Verify empty or truncated signatures, keys, and policy inputs fail closed."""
        valid_policy = create_baseline_test_policy()
        _, valid_sig = sign_policy(valid_policy, self.test_issuer_sig)

        # Empty signature bytes
        res_empty_sig = verify_policy(valid_policy, b"", self.test_issuer_public_key)
        self.assertFalse(res_empty_sig.is_valid)
        self.assertEqual(res_empty_sig.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Truncated signature bytes (e.g. 64 bytes instead of 3309)
        res_trunc_sig = verify_policy(valid_policy, b"\x00" * 64, self.test_issuer_public_key)
        self.assertFalse(res_trunc_sig.is_valid)
        self.assertEqual(res_trunc_sig.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Empty public key bytes
        res_empty_pk = verify_policy(valid_policy, valid_sig, b"")
        self.assertFalse(res_empty_pk.is_valid)
        self.assertEqual(res_empty_pk.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Empty policy bytes
        res_empty_bytes = verify_policy(b"", valid_sig, self.test_issuer_public_key)
        self.assertFalse(res_empty_bytes.is_valid)
        self.assertEqual(res_empty_bytes.status, PolicyVerificationStatus.INVALID_STRUCTURE)

        # Non-mapping, non-bytes policy_input (e.g. integer or list)
        res_invalid_type = verify_policy(12345, valid_sig, self.test_issuer_public_key)  # type: ignore
        self.assertFalse(res_invalid_type.is_valid)
        self.assertEqual(res_invalid_type.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_26_native_oqs_signature_freed_on_success_and_failure(self) -> None:
        """26. Verify oqs.Signature.free() is called on both successful and failed verification."""
        valid_policy = create_baseline_test_policy()
        _, valid_sig = sign_policy(valid_policy, self.test_issuer_sig)
        free_calls = []
        real_free = oqs.Signature.free

        def spy_free(self_obj):
            free_calls.append(id(self_obj))
            return real_free(self_obj)

        with patch.object(oqs.Signature, "free", autospec=True, side_effect=spy_free):
            # Success case
            res_valid = verify_policy(valid_policy, valid_sig, self.test_issuer_public_key)
            self.assertTrue(res_valid.is_valid)
            self.assertEqual(len(free_calls), 1, "oqs.Signature.free must be called on success.")

            # Crypto failure case (tampered signature)
            tampered_sig = bytearray(valid_sig)
            tampered_sig[0] ^= 0x01
            res_invalid = verify_policy(valid_policy, bytes(tampered_sig), self.test_issuer_public_key)
            self.assertFalse(res_invalid.is_valid)
            self.assertEqual(len(free_calls), 2, "oqs.Signature.free must be called on crypto failure.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
