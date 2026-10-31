"""
QERIS Signed Policy Unit Tests
Milestone: Demo 1 — Standalone Signed-Policy Proof of Concept (Updated to Canonical 5-Field Policy Schema)
Author: S1 (Cryptography and Device Engineer)

Scope & Viva Notes:
- Standard-library unittest suite validating standalone signed-policy operations.
- Uses real liboqs-python calls with algorithm ML-DSA-65 for cryptographic tests.
- Conforms strictly to S2's canonical 5-field policy schema:
  - flow_id: str
  - sensitivity: str (LOW, MEDIUM, HIGH, CRITICAL)
  - minimum_mode: str (CLASSICAL, HYBRID, PQC)
  - policy_version: int >= 1
  - authority_id: str
- Comprehensive test coverage:
   1. ML-DSA-65 availability in the installed library.
   2. Valid policy signature accepted with matching public key.
   3. Policy alteration rejected.
   4. Signature alteration rejected.
   5. Verification with a different valid TEST ONLY public key rejected.
   6. WRONG_ALGORITHM returned for a mismatched sig_alg.
   6b. Supplementary control-flow test: crypto verifier is not instantiated on wrong algorithm.
   7. Unsupported signing algorithm rejected.
   8. Missing required canonical fields and unexpected extra fields rejected.
   9. Malformed serialized input rejected.
  10. Invalid policy field types and invalid last_seen_version types rejected.
  11. Lower version rejected as STALE_POLICY on authentic policy.
  12. Equal-version behavior matches documented rule.
  13. Deterministic serialization for equivalent mappings with different key insertion orders.
  14. Deterministic nested / multi-key serialization.
  15. Unsupported JSON values fail clearly.
  16. Any changed security-relevant field cannot pass signature verification.
  17. Forged lower-version policy rejected with INVALID_SIGNATURE (never STALE_POLICY).
  18. Strict JSON deserialization rejects duplicate keys.
  19. Strict JSON deserialization rejects non-standard constants (NaN, Infinity, -Infinity).
  20. Authority registry resolution and UNTRUSTED_AUTHORITY rejection.
  21. Unpaired Unicode surrogates fail cleanly during UTF-8 serialization.
  22. Allowed-algorithms configuration type and content validation.
  23. Authentic higher-version policy accepted as VALID.
  24. Caller stored version state cannot be advanced on verification failure.
  25. Truncated or empty signatures, keys, and policy inputs fail closed.
  26. Native oqs.Signature instances freed on both success and failure.
  27. Explicit signed policy envelope serialization and verification.
- Security constraints:
  - Ephemeral TEST ONLY keys; never production keys.
  - Never logs or prints private keys or secret material.
"""

from collections.abc import Mapping
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
    CANONICAL_POLICY_FIELDS,
    deserialize_policy_from_bytes,
    serialize_policy_to_bytes,
)
from qeris.policy.signed_policy import (
    DEFAULT_SIG_ALG,
    PolicyValidationError,
    PolicyVerificationResult,
    PolicyVerificationStatus,
    SignedPolicyEnvelope,
    create_signed_envelope,
    sign_policy,
    validate_allowed_algorithms,
    validate_policy_structure,
    verify_policy,
)


def create_baseline_test_policy(**overrides: Any) -> dict[str, Any]:
    """Helper to construct a baseline canonical 5-field policy for test fixtures.
    Labeled: TEST ONLY.
    """
    policy = {
        "flow_id": "temperature_01",
        "sensitivity": "LOW",
        "minimum_mode": "CLASSICAL",
        "policy_version": 1,
        "authority_id": "QERIS-GATEWAY",
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
        cls.authority_registry = {"QERIS-GATEWAY": cls.test_issuer_public_key}

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
        policy = create_baseline_test_policy(policy_version=1)
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
        policy = create_baseline_test_policy(policy_version=1)
        signed_bytes, signature = sign_policy(policy, self.test_issuer_sig)

        # Tamper with policy data (e.g. elevate version)
        tampered_policy = create_baseline_test_policy(policy_version=2)
        result = verify_policy(
            policy_input=tampered_policy,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)

        # Tamper with serialized bytes where JSON remains syntactically valid
        tampered_bytes = signed_bytes.replace(b'"policy_version":1', b'"policy_version":2')
        result_bytes = verify_policy(
            policy_input=tampered_bytes,
            signature=signature,
            issuer_public_key=self.test_issuer_public_key,
        )
        self.assertFalse(result_bytes.is_valid)
        self.assertEqual(result_bytes.status, PolicyVerificationStatus.INVALID_SIGNATURE)

    def test_04_modified_signature_fails_verification(self) -> None:
        """4. Verify a modified signature fails verification."""
        policy = create_baseline_test_policy(policy_version=1)
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
        policy = create_baseline_test_policy(policy_version=1)
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
        policy = create_baseline_test_policy()
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        result = verify_policy(
            policy_input=policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
            sig_alg="ML-DSA-44",
            allowed_algorithms=("ML-DSA-65",),
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.WRONG_ALGORITHM)
        self.assertEqual(result.status, "WRONG_ALGORITHM")

    def test_06b_wrong_sig_alg_skips_cryptographic_verification_call(self) -> None:
        """6b. Supplementary control-flow test: verifies oqs.Signature is not instantiated
        when sig_alg is not in the allowed algorithms list."""
        policy = create_baseline_test_policy()
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
                sig_alg="ML-DSA-44",
                allowed_algorithms=("ML-DSA-65",),
            )

        self.assertEqual(result.status, PolicyVerificationStatus.WRONG_ALGORITHM)
        self.assertEqual(len(calls), 0, "oqs.Signature must not be instantiated when algorithm is disallowed.")

    def test_07_unsupported_signing_algorithm_rejected(self) -> None:
        """7. Verify an unsupported signing algorithm is rejected."""
        policy = create_baseline_test_policy()
        dummy_sig = b"\x00" * 64
        dummy_pk = b"\x00" * 64

        result = verify_policy(
            policy_input=policy,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
            sig_alg="NONEXISTENT-PQC-SIG-999",
            allowed_algorithms=("NONEXISTENT-PQC-SIG-999",),
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.status, PolicyVerificationStatus.UNSUPPORTED_ALGORITHM)

    def test_08_missing_required_canonical_fields_and_extras_rejected(self) -> None:
        """8. Verify missing required canonical fields or unexpected extras are rejected with INVALID_STRUCTURE."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        # 8a. Test missing canonical fields
        for field in CANONICAL_POLICY_FIELDS:
            policy = create_baseline_test_policy()
            del policy[field]
            result = verify_policy(
                policy_input=policy,
                signature=dummy_sig,
                issuer_public_key=dummy_pk,
            )
            self.assertFalse(result.is_valid)
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_STRUCTURE)

        # 8b. Test unexpected non-canonical field rejected
        policy_with_extra = create_baseline_test_policy(extra_rogue_field="unauthorized")
        result_extra = verify_policy(
            policy_input=policy_with_extra,
            signature=dummy_sig,
            issuer_public_key=dummy_pk,
        )
        self.assertFalse(result_extra.is_valid)
        self.assertEqual(result_extra.status, PolicyVerificationStatus.INVALID_STRUCTURE)

    def test_09_malformed_serialized_input_rejected(self) -> None:
        """9. Verify malformed serialized input (invalid UTF-8, truncated JSON, non-object JSON) is rejected."""
        dummy_sig = b"\x00" * 3309
        dummy_pk = b"\x00" * 1952

        malformed_cases = [
            b"this-is-not-valid-json",
            b'{"flow_id": "temp_01", "policy_version":',  # truncated JSON
            b"[1, 2, 3]",                                  # JSON list instead of object
            b"\xff\xfe\x00\x00",                           # invalid UTF-8
            b'"just-a-string"',                            # JSON string instead of object
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
            ("flow_id", 123),                  # int instead of str
            ("flow_id", "   "),                # empty / whitespace-only
            ("sensitivity", 1),                # int instead of str
            ("sensitivity", "EXTREME_SECRET"), # invalid enum value
            ("minimum_mode", 99),              # int instead of str
            ("minimum_mode", "SUPER_QUANTUM"), # invalid enum value
            ("policy_version", True),          # boolean instead of int
            ("policy_version", "1"),           # string instead of int
            ("policy_version", 1.5),           # float instead of int
            ("policy_version", 0),             # non-positive int
            ("policy_version", -1),            # negative int
            ("authority_id", 456),             # int instead of str
            ("authority_id", "  "),            # empty / whitespace-only
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
        policy = create_baseline_test_policy(policy_version=1)
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
        policy = create_baseline_test_policy(policy_version=2)
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
        """13. Verify canonical serialization produces deterministic bytes regardless of key insertion order."""
        dict1 = {
            "flow_id": "temp_01",
            "sensitivity": "LOW",
            "minimum_mode": "CLASSICAL",
            "policy_version": 1,
            "authority_id": "QERIS-GATEWAY",
        }
        dict2 = {
            "authority_id": "QERIS-GATEWAY",
            "policy_version": 1,
            "minimum_mode": "CLASSICAL",
            "sensitivity": "LOW",
            "flow_id": "temp_01",
        }
        bytes1 = serialize_policy_to_bytes(dict1)
        bytes2 = serialize_policy_to_bytes(dict2)
        self.assertEqual(bytes1, bytes2)

        # Deserialization roundtrip
        roundtrip = deserialize_policy_from_bytes(bytes1)
        self.assertEqual(roundtrip, dict1)

    def test_14_deterministic_serialization_reproducibility(self) -> None:
        """14. Verify repeated serialization of canonical policies yields exact identical byte sequences."""
        p1 = create_baseline_test_policy(flow_id="heart_rate_flow", sensitivity="CRITICAL", minimum_mode="PQC")
        b1 = serialize_policy_to_bytes(p1)
        b2 = serialize_policy_to_bytes(p1)
        self.assertEqual(b1, b2)
        # Expected deterministic format: sorted keys, separators=(',', ':')
        expected_bytes = b'{"authority_id":"QERIS-GATEWAY","flow_id":"heart_rate_flow","minimum_mode":"PQC","policy_version":1,"sensitivity":"CRITICAL"}'
        self.assertEqual(b1, expected_bytes)

    def test_15_unsupported_json_values_fail_clearly(self) -> None:
        """15. Verify unsupported JSON values (sets, NaN, non-serializable objects) fail clearly."""
        # Non-serializable set
        policy_with_set = create_baseline_test_policy(flow_id={"set_item"})  # type: ignore
        with self.assertRaises((ValueError, TypeError)):
            serialize_policy_to_bytes(policy_with_set)

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
        """16. Verify that modifying any individual canonical field causes verification failure."""
        baseline_policy = create_baseline_test_policy(policy_version=1)
        signed_bytes, signature = sign_policy(baseline_policy, self.test_issuer_sig)

        tamper_variations = [
            ("flow_id", "tampered_flow_99"),
            ("sensitivity", "CRITICAL"),
            ("minimum_mode", "PQC"),
            ("policy_version", 2),
            ("authority_id", "ROGUE-AUTHORITY"),
        ]

        for field_name, altered_val in tamper_variations:
            mutated_policy = create_baseline_test_policy()
            mutated_policy[field_name] = altered_val

            result = verify_policy(
                policy_input=mutated_policy,
                signature=signature,
                issuer_public_key=self.test_issuer_public_key,
            )
            self.assertFalse(
                result.is_valid,
                f"Modifying security-relevant field '{field_name}' must fail verification.",
            )
            self.assertEqual(result.status, PolicyVerificationStatus.INVALID_SIGNATURE)

    def test_17_forged_lower_version_policy_rejected_as_invalid_signature_not_stale(self) -> None:
        """17. Prove that a forged lower-version policy fails with INVALID_SIGNATURE, not STALE_POLICY.
        (Authenticates origin strictly before evaluating anti-rollback version logic)."""
        # Lower-version policy with forged signature
        forged_policy = create_baseline_test_policy(policy_version=1)
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
        """18. Strict JSON deserialization rejects duplicate keys."""
        top_dup = b'{"flow_id":"t1","sensitivity":"LOW","flow_id":"t2","minimum_mode":"CLASSICAL","policy_version":1,"authority_id":"QERIS-GATEWAY"}'
        with self.assertRaises(ValueError) as ctx:
            deserialize_policy_from_bytes(top_dup)
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
        nan_payload = b'{"flow_id":"t1","sensitivity":"LOW","minimum_mode":"CLASSICAL","policy_version":NaN,"authority_id":"QERIS-GATEWAY"}'
        inf_payload = b'{"flow_id":"t1","sensitivity":"LOW","minimum_mode":"CLASSICAL","policy_version":Infinity,"authority_id":"QERIS-GATEWAY"}'
        neginf_payload = b'{"flow_id":"t1","sensitivity":"LOW","minimum_mode":"CLASSICAL","policy_version":-Infinity,"authority_id":"QERIS-GATEWAY"}'

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

    def test_20_authority_registry_resolution_and_untrusted_authority_rejection(self) -> None:
        """20. Authority resolution verifies via authority_registry; rejects unknown authorities."""
        policy = create_baseline_test_policy(authority_id="QERIS-GATEWAY")
        _, signature = sign_policy(policy, self.test_issuer_sig)

        # 20a. Trusted authority in registry
        res_trusted = verify_policy(
            policy_input=policy,
            signature=signature,
            authority_registry=self.authority_registry,
        )
        self.assertTrue(res_trusted.is_valid)
        self.assertEqual(res_trusted.status, PolicyVerificationStatus.VALID)

        # 20b. Untrusted authority not in registry
        untrusted_policy = create_baseline_test_policy(authority_id="ROGUE-AUTHORITY-01")
        _, rogue_sig = sign_policy(untrusted_policy, self.test_issuer_sig)
        res_untrusted = verify_policy(
            policy_input=untrusted_policy,
            signature=rogue_sig,
            authority_registry=self.authority_registry,
        )
        self.assertFalse(res_untrusted.is_valid)
        self.assertEqual(res_untrusted.status, PolicyVerificationStatus.UNTRUSTED_AUTHORITY)
        self.assertIn("not in trusted authority registry", res_untrusted.message)

    def test_21_unpaired_unicode_surrogate_fails_cleanly(self) -> None:
        """21. Unpaired Unicode surrogates fail cleanly during UTF-8 serialization and validation."""
        surrogate_policy = create_baseline_test_policy(flow_id="temp_\ud800_sensor")

        # Direct serialize_policy_to_bytes raises ValueError
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
        """23. Verify an authentic policy with policy_version > last_seen_version is accepted as VALID."""
        policy = create_baseline_test_policy(policy_version=3)
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
        forged_policy = create_baseline_test_policy(policy_version=10)
        forged_signature = b"\x00" * 3309
        result_forged = verify_policy(
            policy_input=forged_policy,
            signature=forged_signature,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=gateway_stored_version,
        )
        self.assertFalse(result_forged.is_valid)
        if result_forged.is_valid:
            gateway_stored_version = forged_policy["policy_version"]
        self.assertEqual(gateway_stored_version, 2, "Stored version must not advance on forged policy.")

        # Case B: Replay of authentic stale policy (version 1)
        stale_policy = create_baseline_test_policy(policy_version=1)
        _, stale_sig = sign_policy(stale_policy, self.test_issuer_sig)
        result_stale = verify_policy(
            policy_input=stale_policy,
            signature=stale_sig,
            issuer_public_key=self.test_issuer_public_key,
            last_seen_version=gateway_stored_version,
        )
        self.assertFalse(result_stale.is_valid)
        if result_stale.is_valid:
            gateway_stored_version = stale_policy["policy_version"]
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

    def test_27_envelope_creation_and_verification(self) -> None:
        """27. Verify SignedPolicyEnvelope creation, serialization and verification."""
        policy = create_baseline_test_policy()
        envelope_dict = create_signed_envelope(policy, self.test_issuer_sig)

        self.assertIn("policy", envelope_dict)
        self.assertIn("sig_alg", envelope_dict)
        self.assertIn("signature", envelope_dict)
        self.assertEqual(envelope_dict["sig_alg"], "ML-DSA-65")

        # Verify via dict envelope
        res_env = verify_policy(envelope_dict, issuer_public_key=self.test_issuer_public_key)
        self.assertTrue(res_env.is_valid)
        self.assertEqual(res_env.status, PolicyVerificationStatus.VALID)

        # Verify via SignedPolicyEnvelope object
        obj_env = SignedPolicyEnvelope.from_dict(envelope_dict)
        res_obj = verify_policy(obj_env, issuer_public_key=self.test_issuer_public_key)
        self.assertTrue(res_obj.is_valid)
        self.assertEqual(res_obj.status, PolicyVerificationStatus.VALID)


if __name__ == "__main__":
    unittest.main(verbosity=2)
