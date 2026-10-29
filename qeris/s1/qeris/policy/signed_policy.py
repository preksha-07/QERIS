"""
QERIS Signed Policy Module
Milestone: Demo 1 — Standalone Signed-Policy Proof of Concept
Author: S1 (Cryptography and Device Engineer)

===============================================================================
SECURITY & SCOPE NOTICES:
1. DEVICE IDENTITY & AUTHORIZATION DISCLAIMER:
   Cryptographic signature verification on a policy proves ONLY that the policy
   was signed by the holder of the issuer private key corresponding to the pinned
   issuer public key. It does NOT prove device identity, nor does it authorize
   any individual IoT edge device. Device authentication and credential registry
   checks are handled separately by the gateway.
2. EXPIRY & REVOCATION STATUS (UNRESOLVED):
   The 'expiry' and 'revocation_list' fields are candidate fields inferred from
   the threat model. Expiry enforcement requires a trusted secure time source
   (currently unestablished on constrained devices), and revocation semantics
   require gateway distribution rules (currently unestablished). These checks are
   flagged as UNRESOLVED and are not claimed to be complete.
3. ANTI-ROLLBACK & PERSISTENCE:
   Monotonic version checking is evaluated in-memory against a caller-supplied
   'last_seen_version'. No persistent storage or storage owner is implemented here;
   persistent anti-rollback storage design must be coordinated with S2/S3.
4. AUTHENTICATION BEFORE ANTI-ROLLBACK:
   Cryptographic signature verification is strictly performed BEFORE any
   anti-rollback decision based on the policy version. An unauthenticated or
   forged policy is rejected with INVALID_SIGNATURE and is never evaluated or
   logged as an authentic stale policy.
5. CONFIDENTIALITY:
   This module never logs or prints private keys, secret signer material, or
   cryptographic secrets.
===============================================================================
"""

from collections.abc import Container, Mapping
from dataclasses import dataclass
from enum import Enum
import math
from typing import Any
import oqs

from .serialization import (
    PROVISIONAL_CANDIDATE_FIELDS,
    deserialize_policy_from_bytes,
    serialize_policy_to_bytes,
)

# Standard approved algorithm name for QERIS Demo 1 policy signing
DEFAULT_SIG_ALG: str = "ML-DSA-65"
DEFAULT_ALLOWED_ALGORITHMS: tuple[str, ...] = ("ML-DSA-65",)

# Maximum safe 64-bit signed integer timestamp (protects against OverflowError and unreasonable ranges)
MAX_EXPIRY_TIMESTAMP: int = (1 << 63) - 1

PERMITTED_ALLOWED_ALGORITHMS_TYPES: tuple[type, ...] = (tuple, list, set, frozenset)


class PolicyValidationError(ValueError):
    """Raised when policy structure or fields fail provisional validation."""
    pass


class PolicyVerificationStatus(str, Enum):
    """Explicit verification status codes."""
    VALID = "VALID"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"
    WRONG_ALGORITHM = "WRONG_ALGORITHM"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    STALE_POLICY = "STALE_POLICY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"


@dataclass(frozen=True)
class PolicyVerificationResult:
    """
    Structured result returned by policy verification.

    - is_valid: True only if structure, algorithm, signature, and monotonic version all pass.
    - status: Specific PolicyVerificationStatus code for granular policy decisions.
    - message: Descriptive technical summary (suitable for logging/viva explanation).
    """
    is_valid: bool
    status: PolicyVerificationStatus
    message: str

    def __bool__(self) -> bool:
        return self.is_valid


def _is_safe_utf8_string(val: str) -> bool:
    """Checks if a string encodes cleanly to UTF-8 without unpaired Unicode surrogates."""
    try:
        val.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def validate_allowed_algorithms(allowed_algorithms: Any) -> frozenset[str]:
    """
    Validates and normalizes the verifier's allowed_algorithms configuration.

    Accepted input types:
        - None: defaults to DEFAULT_ALLOWED_ALGORITHMS.
        - tuple, list, set, frozenset containing non-empty, non-whitespace strings.

    Rejected:
        - str, bytes, bytearray (rejects string-as-container vulnerabilities).
        - Non-iterables or collections containing non-string or empty elements.

    Returns:
        frozenset[str]: Normalized set of permitted algorithm identifiers.

    Raises:
        TypeError: If allowed_algorithms is not a permitted collection type or contains non-string items.
        ValueError: If any algorithm name is empty or whitespace-only.
    """
    if allowed_algorithms is None:
        return frozenset(DEFAULT_ALLOWED_ALGORITHMS)

    # Strictly reject str, bytes, bytearray to prevent accidental substring matching
    if isinstance(allowed_algorithms, (str, bytes, bytearray)):
        raise TypeError(
            f"allowed_algorithms must be a tuple, list, set, or frozenset, not {type(allowed_algorithms).__name__}"
        )

    if not isinstance(allowed_algorithms, PERMITTED_ALLOWED_ALGORITHMS_TYPES):
        raise TypeError(
            f"allowed_algorithms must be a tuple, list, set, or frozenset, not {type(allowed_algorithms).__name__}"
        )

    normalized: set[str] = set()
    for item in allowed_algorithms:
        if not isinstance(item, str):
            raise TypeError(
                f"All elements in allowed_algorithms must be strings, got {item!r} ({type(item).__name__})"
            )
        if not item.strip():
            raise ValueError(
                f"Algorithm names in allowed_algorithms cannot be empty or whitespace-only, got {item!r}"
            )
        normalized.add(item)

    return frozenset(normalized)


def validate_policy_structure(
    policy: Mapping[str, Any],
    raise_exception: bool = False,
) -> tuple[PolicyVerificationStatus, str]:
    """
    Validates structural integrity and presence of provisional candidate fields.

    Documented provisional schema rules:
    - version: Positive integer (>= 1, strictly not boolean).
    - sig_alg: Non-empty string without unpaired surrogates.
    - flow_to_tier: Dict mapping string flow identifiers to string tiers.
    - tier_to_suite: Dict mapping string tiers to string cryptographic suites.
    - expiry: Safe numeric timestamp (int or float, not boolean, not NaN/Inf, 0 <= expiry <= 2^63 - 1).
    - revocation_list: List of revoked device/credential ID strings.
    """
    if not isinstance(policy, Mapping):
        msg = f"Policy input must be a dictionary or mapping, got {type(policy).__name__}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # Verify all candidate fields are present in the provisional test schema
    for field in PROVISIONAL_CANDIDATE_FIELDS:
        if field not in policy:
            msg = f"Missing required provisional policy field: '{field}'"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # Field-specific structural and type assertions
    version = policy["version"]
    if type(version) is not int or version < 1:
        msg = f"Field 'version' must be an integer >= 1, got {version!r} (type {type(version).__name__})"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    sig_alg = policy["sig_alg"]
    if not isinstance(sig_alg, str) or not sig_alg.strip():
        msg = f"Field 'sig_alg' must be a non-empty string, got {sig_alg!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    if not _is_safe_utf8_string(sig_alg):
        msg = f"Field 'sig_alg' contains invalid Unicode surrogates: {sig_alg!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    flow_to_tier = policy["flow_to_tier"]
    if not isinstance(flow_to_tier, dict):
        msg = f"Field 'flow_to_tier' must be a dict, got {type(flow_to_tier).__name__}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    for k, v in flow_to_tier.items():
        if not isinstance(k, str) or not isinstance(v, str):
            msg = f"Field 'flow_to_tier' must contain string keys and values, got ({k!r}: {v!r})"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg
        if not _is_safe_utf8_string(k) or not _is_safe_utf8_string(v):
            msg = f"Field 'flow_to_tier' contains invalid Unicode surrogates in ({k!r}: {v!r})"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    tier_to_suite = policy["tier_to_suite"]
    if not isinstance(tier_to_suite, dict):
        msg = f"Field 'tier_to_suite' must be a dict, got {type(tier_to_suite).__name__}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    for k, v in tier_to_suite.items():
        if not isinstance(k, str) or not isinstance(v, str):
            msg = f"Field 'tier_to_suite' must contain string keys and values, got ({k!r}: {v!r})"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg
        if not _is_safe_utf8_string(k) or not _is_safe_utf8_string(v):
            msg = f"Field 'tier_to_suite' contains invalid Unicode surrogates in ({k!r}: {v!r})"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    expiry = policy["expiry"]
    if type(expiry) not in (int, float) or isinstance(expiry, bool):
        msg = f"Field 'expiry' must be a numeric timestamp, got {expiry!r} (type {type(expiry).__name__})"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # Safe timestamp validation: prevents OverflowError on huge integers
    if isinstance(expiry, float):
        if math.isnan(expiry) or math.isinf(expiry) or expiry < 0 or expiry > MAX_EXPIRY_TIMESTAMP:
            msg = f"Field 'expiry' must be a finite, non-negative timestamp <= {MAX_EXPIRY_TIMESTAMP}, got {expiry!r}"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    else:  # int: compared directly without float conversion to avoid OverflowError
        if expiry < 0 or expiry > MAX_EXPIRY_TIMESTAMP:
            msg = f"Field 'expiry' integer timestamp out of range (0 to {MAX_EXPIRY_TIMESTAMP}), got {expiry!r}"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    revocation_list = policy["revocation_list"]
    if not isinstance(revocation_list, list):
        msg = f"Field 'revocation_list' must be a list, got {type(revocation_list).__name__}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    for item in revocation_list:
        if not isinstance(item, str):
            msg = f"Field 'revocation_list' must contain only string IDs, got item {item!r} ({type(item).__name__})"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg
        if not _is_safe_utf8_string(item):
            msg = f"Field 'revocation_list' contains invalid Unicode surrogates in item {item!r}"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    return PolicyVerificationStatus.VALID, "Policy structure is valid."


def sign_policy(
    policy_data: Mapping[str, Any],
    signer: oqs.Signature | bytes,
    sig_alg: str = DEFAULT_SIG_ALG,
) -> tuple[bytes, bytes]:
    """
    Serializes policy data and signs it using ML-DSA-65 (or specified algorithm).

    Args:
        policy_data: Policy mapping containing all required fields including 'sig_alg'.
        signer: Active oqs.Signature object with private key loaded, or raw private key bytes.
        sig_alg: Cryptographic signature algorithm name (default: 'ML-DSA-65').

    Returns:
        tuple (signed_bytes, signature):
            signed_bytes: The deterministic serialized UTF-8 bytes covered by the signature.
            signature: The raw cryptographic signature bytes.

    Security Notes:
        - 'sig_alg' is explicitly covered in the signed data to prevent algorithm confusion.
        - Private keys are never logged, printed, or leaked.
        - Any ephemeral oqs.Signature object created from raw secret key bytes is freed in finally.
    """
    # Structural check before signing
    validate_policy_structure(policy_data, raise_exception=True)

    if policy_data.get("sig_alg") != sig_alg:
        raise ValueError(
            f"Policy sig_alg '{policy_data.get('sig_alg')}' does not match signer algorithm '{sig_alg}'"
        )

    signed_bytes = serialize_policy_to_bytes(policy_data)

    if isinstance(signer, oqs.Signature):
        signature = signer.sign(signed_bytes)
        return signed_bytes, signature
    elif isinstance(signer, (bytes, bytearray)):
        sig_instance = None
        try:
            sig_instance = oqs.Signature(sig_alg, secret_key=bytes(signer))
            signature = sig_instance.sign(signed_bytes)
            return signed_bytes, signature
        finally:
            if sig_instance is not None:
                sig_instance.free()
    else:
        raise TypeError(f"Signer must be an oqs.Signature or raw secret key bytes, got {type(signer).__name__}")


def verify_policy(
    policy_input: Mapping[str, Any] | bytes,
    signature: bytes,
    issuer_public_key: bytes,
    allowed_algorithms: Container[str] | None = None,
    last_seen_version: int | None = None,
    allow_equal_version: bool = True,
) -> PolicyVerificationResult:
    """
    Verifies the structure, algorithm, signature, and monotonic version of a policy.

    Order of Operations (Authentication Before Anti-Rollback):
    1. Caller parameter validation (allowed_algorithms, last_seen_version, allow_equal_version).
    2. Input ingestion and strict JSON parsing.
    3. Structural and field type validation.
    4. Algorithm allowlisting (rejected before crypto operations if disallowed).
    5. Cryptographic signature verification (proves authentic issuer origin).
    6. Monotonic anti-rollback check (evaluated strictly on authenticated policies).

    Documented Version Rules:
    - Evaluated ONLY after signature verification succeeds.
    - If policy.version < last_seen_version: Rejected with STALE_POLICY (anti-rollback).
    - If policy.version == last_seen_version:
        * If allow_equal_version is True (default): Permitted (idempotent policy re-broadcast).
        * If allow_equal_version is False: Rejected with STALE_POLICY (strictly monotonic).
    - If policy.version > last_seen_version: Accepted as a valid version increment.

    Documented Algorithm Rules:
    - The 'sig_alg' specified in the policy MUST be in allowed_algorithms.
    - If 'sig_alg' is not allowed, returns WRONG_ALGORITHM BEFORE cryptographic verification.
    - If 'sig_alg' is allowed but not supported by liboqs, returns UNSUPPORTED_ALGORITHM.

    Args:
        policy_input: Either the policy dictionary or the serialized canonical policy bytes.
        signature: Raw cryptographic signature bytes.
        issuer_public_key: Pinned issuer public key bytes.
        allowed_algorithms: Permitted algorithms (tuple, list, set, frozenset, or None).
        last_seen_version: Previously observed active policy version (must be int >= 0 or None).
        allow_equal_version: Whether re-announcing the same version is allowed (default: True).

    Returns:
        PolicyVerificationResult containing is_valid, status, and descriptive message.
    """
    # 1. Validate caller-supplied verification parameters
    normalized_allowed = validate_allowed_algorithms(allowed_algorithms)

    if last_seen_version is not None:
        if type(last_seen_version) is not int or isinstance(last_seen_version, bool) or last_seen_version < 0:
            raise TypeError(
                f"last_seen_version must be a non-negative integer or None, got {last_seen_version!r} (type {type(last_seen_version).__name__})"
            )

    if not isinstance(allow_equal_version, bool):
        raise TypeError(f"allow_equal_version must be a bool, got {type(allow_equal_version).__name__}")

    if not isinstance(issuer_public_key, (bytes, bytearray)):
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_STRUCTURE,
            message=f"issuer_public_key must be bytes or bytearray, got {type(issuer_public_key).__name__}",
        )

    if not isinstance(signature, (bytes, bytearray)):
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_STRUCTURE,
            message=f"signature must be bytes or bytearray, got {type(signature).__name__}",
        )

    # 2. Structural Ingestion & Parsing
    if isinstance(policy_input, (bytes, bytearray)):
        raw_bytes = bytes(policy_input)
        try:
            policy_dict = deserialize_policy_from_bytes(raw_bytes)
        except Exception as exc:
            return PolicyVerificationResult(
                is_valid=False,
                status=PolicyVerificationStatus.INVALID_STRUCTURE,
                message=f"Failed to parse policy bytes: {exc}",
            )
    elif isinstance(policy_input, Mapping):
        policy_dict = dict(policy_input)
        try:
            raw_bytes = serialize_policy_to_bytes(policy_dict)
        except Exception as exc:
            return PolicyVerificationResult(
                is_valid=False,
                status=PolicyVerificationStatus.INVALID_STRUCTURE,
                message=f"Failed to serialize policy mapping: {exc}",
            )
    else:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_STRUCTURE,
            message=f"Unsupported policy input type: {type(policy_input).__name__}",
        )

    # 3. Structural & Field Validation
    struct_status, struct_msg = validate_policy_structure(policy_dict, raise_exception=False)
    if struct_status != PolicyVerificationStatus.VALID:
        return PolicyVerificationResult(
            is_valid=False,
            status=struct_status,
            message=struct_msg,
        )

    # 4. Algorithm Validation (Checked strictly BEFORE cryptographic operations)
    sig_alg = policy_dict["sig_alg"]
    if sig_alg not in normalized_allowed:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.WRONG_ALGORITHM,
            message=f"Algorithm '{sig_alg}' is not in configured allowed algorithms: {sorted(normalized_allowed)}",
        )

    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    if sig_alg not in enabled_sigs:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.UNSUPPORTED_ALGORITHM,
            message=f"Algorithm '{sig_alg}' is not enabled in local liboqs installation.",
        )

    # 5. Cryptographic Signature Verification (Authentication)
    sig_verifier = None
    try:
        sig_verifier = oqs.Signature(sig_alg)
        is_crypto_valid = sig_verifier.verify(raw_bytes, bytes(signature), bytes(issuer_public_key))
        if not is_crypto_valid:
            return PolicyVerificationResult(
                is_valid=False,
                status=PolicyVerificationStatus.INVALID_SIGNATURE,
                message="Cryptographic signature verification returned False (tampered policy or signature mismatch).",
            )
    except Exception as exc:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_SIGNATURE,
            message=f"Cryptographic verification error: {exc}",
        )
    finally:
        if sig_verifier is not None:
            sig_verifier.free()

    # 6. Monotonic Version Check (Anti-Rollback)
    # Performed strictly AFTER cryptographic signature verification confirms authenticity
    version = policy_dict["version"]
    if last_seen_version is not None:
        if version < last_seen_version:
            return PolicyVerificationResult(
                is_valid=False,
                status=PolicyVerificationStatus.STALE_POLICY,
                message=f"Policy version {version} is lower than last seen version {last_seen_version} (STALE_POLICY).",
            )
        elif version == last_seen_version and not allow_equal_version:
            return PolicyVerificationResult(
                is_valid=False,
                status=PolicyVerificationStatus.STALE_POLICY,
                message=f"Policy version {version} equals last seen version {last_seen_version} under strict monotonic policy.",
            )

    return PolicyVerificationResult(
        is_valid=True,
        status=PolicyVerificationStatus.VALID,
        message="Policy signature, structure, algorithm, and monotonic version successfully verified.",
    )
