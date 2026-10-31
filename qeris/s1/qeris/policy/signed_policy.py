"""
QERIS Signed Policy Module
Milestone: Complete Backend Integration (S1-S2 Policy Schema Alignment)
Author: S1 (Cryptography and Device Engineer) & S2 (Gateway Engineer)

===============================================================================
SECURITY & ARCHITECTURAL CONTRACT:
1. CANONICAL FIVE-FIELD POLICY:
   The policy format strictly matches S2's five-field schema:
   - flow_id: str
   - sensitivity: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
   - minimum_mode: str ("CLASSICAL", "HYBRID", "PQC")
   - policy_version: int (>= 1, strictly not bool)
   - authority_id: str
   Provisional candidate fields from Demo 1 (expiry, revocation_list,
   tier_to_suite, flow_to_tier, sig_alg inside payload) are removed from active
   validation.
2. EXPLICIT SIGNATURE ENVELOPE:
   The policy payload is decoupled from signature metadata. An envelope contains:
   - policy: The canonical 5-field mapping.
   - sig_alg: Cryptographic algorithm identifier (ML-DSA-65).
   - signature: Cryptographic signature bytes (or hex string).
3. TRUSTED AUTHORITY RESOLUTION:
   authority_id is verified against a trusted public-key registry. Unregistered
   or untrusted authorities are rejected with UNTRUSTED_AUTHORITY.
   Public keys supplied inside unverified policies are NEVER trusted.
4. AUTHENTICATION BEFORE ANTI-ROLLBACK:
   Cryptographic signature verification strictly occurs BEFORE checking policy
   version anti-rollback. An invalid signature returns INVALID_SIGNATURE.
5. CONFIDENTIALITY:
   Private keys and secret signer material are never logged, printed, or leaked.
===============================================================================
"""

from collections.abc import Container, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
import oqs

from .serialization import (
    CANONICAL_POLICY_FIELDS,
    deserialize_envelope_from_bytes,
    deserialize_policy_from_bytes,
    serialize_envelope_to_bytes,
    serialize_policy_to_bytes,
)

# Standard approved algorithm name for QERIS policy signing
DEFAULT_SIG_ALG: str = "ML-DSA-65"
DEFAULT_ALLOWED_ALGORITHMS: tuple[str, ...] = ("ML-DSA-65",)

PERMITTED_ALLOWED_ALGORITHMS_TYPES: tuple[type, ...] = (tuple, list, set, frozenset)

VALID_SENSITIVITIES: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
VALID_MODES: frozenset[str] = frozenset({"CLASSICAL", "HYBRID", "PQC", "PQ"})


class PolicyValidationError(ValueError):
    """Raised when policy structure or fields fail validation."""
    pass


class PolicyVerificationStatus(str, Enum):
    """Explicit policy verification status codes."""
    VALID = "VALID"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"
    WRONG_ALGORITHM = "WRONG_ALGORITHM"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    STALE_POLICY = "STALE_POLICY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNTRUSTED_AUTHORITY = "UNTRUSTED_AUTHORITY"


@dataclass(frozen=True)
class PolicyVerificationResult:
    """Structured result returned by policy verification.

    - is_valid: True only if structure, authority, algorithm, signature, and monotonic version pass.
    - status: Specific PolicyVerificationStatus code.
    - message: Descriptive technical summary.
    """
    is_valid: bool
    status: PolicyVerificationStatus
    message: str

    def __bool__(self) -> bool:
        return self.is_valid


@dataclass(frozen=True)
class SignedPolicyEnvelope:
    """Explicit envelope decoupling the 5-field policy from signature metadata."""
    policy: dict[str, Any]
    sig_alg: str = DEFAULT_SIG_ALG
    signature: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        """Convert envelope to JSON-serializable dictionary with hex signature."""
        return {
            "policy": dict(self.policy),
            "sig_alg": self.sig_alg,
            "signature": self.signature.hex() if isinstance(self.signature, (bytes, bytearray)) else str(self.signature),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SignedPolicyEnvelope":
        """Instantiate envelope from a dictionary."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Envelope data must be a Mapping, got {type(data).__name__}")
        if "policy" not in data or "signature" not in data:
            raise ValueError("Envelope must contain 'policy' and 'signature' fields.")
        policy = dict(data["policy"])
        sig_alg = str(data.get("sig_alg", DEFAULT_SIG_ALG))
        raw_sig = data["signature"]
        if isinstance(raw_sig, str):
            sig_bytes = bytes.fromhex(raw_sig)
        elif isinstance(raw_sig, (bytes, bytearray)):
            sig_bytes = bytes(raw_sig)
        else:
            raise TypeError(f"Signature must be hex string or bytes, got {type(raw_sig).__name__}")
        return cls(policy=policy, sig_alg=sig_alg, signature=sig_bytes)


def _is_safe_utf8_string(val: str) -> bool:
    """Checks if a string encodes cleanly to UTF-8 without unpaired Unicode surrogates."""
    try:
        val.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def validate_allowed_algorithms(allowed_algorithms: Any) -> frozenset[str]:
    """Validates and normalizes the verifier's allowed_algorithms configuration."""
    if allowed_algorithms is None:
        return frozenset(DEFAULT_ALLOWED_ALGORITHMS)

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
    """Validates structural integrity and presence of canonical 5-field schema.

    Canonical Schema Fields:
    - flow_id: non-empty string.
    - sensitivity: string in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}.
    - minimum_mode: string in {"CLASSICAL", "HYBRID", "PQC", "PQ"}.
    - policy_version: integer >= 1 (strictly not bool).
    - authority_id: non-empty string.
    """
    if not isinstance(policy, Mapping):
        msg = f"Policy input must be a dictionary or mapping, got {type(policy).__name__}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # Reject missing canonical fields
    for field in CANONICAL_POLICY_FIELDS:
        if field not in policy:
            msg = f"Missing required canonical policy field: '{field}'"
            if raise_exception:
                raise PolicyValidationError(msg)
            return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # Reject unknown extra fields in canonical policy
    extra_fields = set(policy.keys()) - set(CANONICAL_POLICY_FIELDS)
    if extra_fields:
        msg = f"Unexpected non-canonical fields in policy: {sorted(extra_fields)}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # 1. flow_id
    flow_id = policy["flow_id"]
    if not isinstance(flow_id, str) or not flow_id.strip():
        msg = f"Field 'flow_id' must be a non-empty string, got {flow_id!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if not _is_safe_utf8_string(flow_id):
        msg = f"Field 'flow_id' contains invalid Unicode surrogates: {flow_id!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # 2. sensitivity
    sensitivity = policy["sensitivity"]
    if not isinstance(sensitivity, str) or not sensitivity.strip():
        msg = f"Field 'sensitivity' must be a non-empty string, got {sensitivity!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if sensitivity.upper() not in VALID_SENSITIVITIES:
        msg = f"Field 'sensitivity' must be one of {sorted(VALID_SENSITIVITIES)}, got {sensitivity!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if not _is_safe_utf8_string(sensitivity):
        msg = f"Field 'sensitivity' contains invalid Unicode surrogates: {sensitivity!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # 3. minimum_mode
    minimum_mode = policy["minimum_mode"]
    if not isinstance(minimum_mode, str) or not minimum_mode.strip():
        msg = f"Field 'minimum_mode' must be a non-empty string, got {minimum_mode!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if minimum_mode.upper() not in VALID_MODES:
        msg = f"Field 'minimum_mode' must be one of {sorted(VALID_MODES)}, got {minimum_mode!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if not _is_safe_utf8_string(minimum_mode):
        msg = f"Field 'minimum_mode' contains invalid Unicode surrogates: {minimum_mode!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # 4. policy_version
    policy_version = policy["policy_version"]
    if type(policy_version) is not int or isinstance(policy_version, bool) or policy_version < 1:
        msg = f"Field 'policy_version' must be an integer >= 1, got {policy_version!r} (type {type(policy_version).__name__})"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    # 5. authority_id
    authority_id = policy["authority_id"]
    if not isinstance(authority_id, str) or not authority_id.strip():
        msg = f"Field 'authority_id' must be a non-empty string, got {authority_id!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg
    if not _is_safe_utf8_string(authority_id):
        msg = f"Field 'authority_id' contains invalid Unicode surrogates: {authority_id!r}"
        if raise_exception:
            raise PolicyValidationError(msg)
        return PolicyVerificationStatus.INVALID_STRUCTURE, msg

    return PolicyVerificationStatus.VALID, "Policy structure is valid."


def sign_policy(
    policy_data: Mapping[str, Any],
    signer: oqs.Signature | bytes,
    sig_alg: str = DEFAULT_SIG_ALG,
) -> tuple[bytes, bytes]:
    """Serializes canonical 5-field policy data and signs it using ML-DSA-65.

    Args:
        policy_data: 5-field canonical policy mapping.
        signer: Active oqs.Signature object with private key loaded, or raw private key bytes.
        sig_alg: Cryptographic signature algorithm name (default: 'ML-DSA-65').

    Returns:
        tuple (signed_bytes, signature):
            signed_bytes: Deterministic serialized UTF-8 bytes covered by the signature.
            signature: Raw cryptographic signature bytes.
    """
    validate_policy_structure(policy_data, raise_exception=True)
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


def create_signed_envelope(
    policy_data: Mapping[str, Any],
    signer: oqs.Signature | bytes,
    sig_alg: str = DEFAULT_SIG_ALG,
) -> dict[str, Any]:
    """Creates a signed policy envelope containing the 5-field policy, sig_alg, and hex signature."""
    _, signature = sign_policy(policy_data, signer, sig_alg=sig_alg)
    return SignedPolicyEnvelope(
        policy=dict(policy_data),
        sig_alg=sig_alg,
        signature=signature,
    ).to_dict()


def verify_policy(
    policy_input: Mapping[str, Any] | bytes | SignedPolicyEnvelope,
    signature: Optional[bytes] = None,
    issuer_public_key: Optional[bytes] = None,
    authority_registry: Optional[Mapping[str, bytes]] = None,
    allowed_algorithms: Container[str] | None = None,
    last_seen_version: int | None = None,
    allow_equal_version: bool = True,
    sig_alg: str = DEFAULT_SIG_ALG,
) -> PolicyVerificationResult:
    """Verifies the structure, trusted authority, algorithm, signature, and monotonic version of a policy.

    Order of Operations (Authentication Before Anti-Rollback):
    1. Caller parameter validation.
    2. Input ingestion and extraction of envelope if provided.
    3. Structural and field type validation on canonical 5 fields.
    4. Authority resolution via authority_registry (or issuer_public_key).
    5. Algorithm allowlisting (rejected before crypto operations if disallowed).
    6. Cryptographic signature verification with ML-DSA-65.
    7. Monotonic anti-rollback check (evaluated strictly on authenticated policies).
    """
    # 1. Parameter validation
    normalized_allowed = validate_allowed_algorithms(allowed_algorithms)

    if last_seen_version is not None:
        if type(last_seen_version) is not int or isinstance(last_seen_version, bool) or last_seen_version < 0:
            raise TypeError(
                f"last_seen_version must be a non-negative integer or None, got {last_seen_version!r} (type {type(last_seen_version).__name__})"
            )

    if not isinstance(allow_equal_version, bool):
        raise TypeError(f"allow_equal_version must be a bool, got {type(allow_equal_version).__name__}")

    # 2. Extract policy, sig_alg, signature from input
    effective_sig_alg = sig_alg
    effective_sig = signature

    if isinstance(policy_input, SignedPolicyEnvelope):
        policy_dict = dict(policy_input.policy)
        effective_sig = policy_input.signature
        effective_sig_alg = policy_input.sig_alg
        try:
            raw_bytes = serialize_policy_to_bytes(policy_dict)
        except Exception as exc:
            return PolicyVerificationResult(False, PolicyVerificationStatus.INVALID_STRUCTURE, str(exc))

    elif isinstance(policy_input, Mapping):
        # Check if this mapping is an envelope (has "policy" and "signature")
        if "policy" in policy_input and "signature" in policy_input:
            env = dict(policy_input)
            inner_policy = env["policy"]
            if not isinstance(inner_policy, Mapping):
                return PolicyVerificationResult(
                    False, PolicyVerificationStatus.INVALID_STRUCTURE, "'policy' in envelope must be a mapping"
                )
            policy_dict = dict(inner_policy)
            effective_sig_alg = str(env.get("sig_alg", sig_alg))
            raw_sig = env["signature"]
            if isinstance(raw_sig, str):
                try:
                    effective_sig = bytes.fromhex(raw_sig)
                except ValueError:
                    return PolicyVerificationResult(
                        False, PolicyVerificationStatus.INVALID_SIGNATURE, "Invalid hex signature in envelope"
                    )
            elif isinstance(raw_sig, (bytes, bytearray)):
                effective_sig = bytes(raw_sig)
            else:
                return PolicyVerificationResult(
                    False, PolicyVerificationStatus.INVALID_STRUCTURE, "Signature in envelope must be hex or bytes"
                )
            try:
                raw_bytes = serialize_policy_to_bytes(policy_dict)
            except Exception as exc:
                return PolicyVerificationResult(False, PolicyVerificationStatus.INVALID_STRUCTURE, str(exc))
        else:
            policy_dict = dict(policy_input)
            try:
                raw_bytes = serialize_policy_to_bytes(policy_dict)
            except Exception as exc:
                return PolicyVerificationResult(False, PolicyVerificationStatus.INVALID_STRUCTURE, str(exc))

    elif isinstance(policy_input, (bytes, bytearray)):
        raw_bytes_in = bytes(policy_input)
        try:
            parsed = deserialize_policy_from_bytes(raw_bytes_in)
        except Exception as exc:
            return PolicyVerificationResult(False, PolicyVerificationStatus.INVALID_STRUCTURE, str(exc))

        # Check if deserialized JSON is an envelope
        if "policy" in parsed and "signature" in parsed:
            inner_policy = parsed["policy"]
            if not isinstance(inner_policy, Mapping):
                return PolicyVerificationResult(
                    False, PolicyVerificationStatus.INVALID_STRUCTURE, "'policy' in envelope must be a mapping"
                )
            policy_dict = dict(inner_policy)
            effective_sig_alg = str(parsed.get("sig_alg", sig_alg))
            raw_sig = parsed["signature"]
            if isinstance(raw_sig, str):
                try:
                    effective_sig = bytes.fromhex(raw_sig)
                except ValueError:
                    return PolicyVerificationResult(
                        False, PolicyVerificationStatus.INVALID_SIGNATURE, "Invalid hex signature in envelope"
                    )
            elif isinstance(raw_sig, (bytes, bytearray)):
                effective_sig = bytes(raw_sig)
            try:
                raw_bytes = serialize_policy_to_bytes(policy_dict)
            except Exception as exc:
                return PolicyVerificationResult(False, PolicyVerificationStatus.INVALID_STRUCTURE, str(exc))
        else:
            policy_dict = parsed
            raw_bytes = raw_bytes_in
    else:
        return PolicyVerificationResult(
            False, PolicyVerificationStatus.INVALID_STRUCTURE, f"Unsupported policy input type: {type(policy_input).__name__}"
        )

    # 3. Structural validation on canonical 5 fields
    struct_status, struct_msg = validate_policy_structure(policy_dict, raise_exception=False)
    if struct_status != PolicyVerificationStatus.VALID:
        return PolicyVerificationResult(False, struct_status, struct_msg)

    # Validate signature bytes presence
    if not isinstance(effective_sig, (bytes, bytearray)):
        return PolicyVerificationResult(
            False, PolicyVerificationStatus.INVALID_SIGNATURE, "Signature must be provided as bytes or bytearray"
        )
    effective_sig = bytes(effective_sig)
    if not effective_sig:
        return PolicyVerificationResult(
            False, PolicyVerificationStatus.INVALID_SIGNATURE, "Signature cannot be empty"
        )

    # 4. Resolve authority public key
    resolved_public_key = issuer_public_key
    authority_id = policy_dict["authority_id"]

    if authority_registry is not None:
        if authority_id not in authority_registry:
            return PolicyVerificationResult(
                False,
                PolicyVerificationStatus.UNTRUSTED_AUTHORITY,
                f"Authority '{authority_id}' is not in trusted authority registry",
            )
        resolved_public_key = authority_registry[authority_id]

    if resolved_public_key is None or not isinstance(resolved_public_key, (bytes, bytearray)):
        return PolicyVerificationResult(
            False,
            PolicyVerificationStatus.UNTRUSTED_AUTHORITY,
            f"No valid public key available for authority '{authority_id}'",
        )
    resolved_public_key = bytes(resolved_public_key)
    if not resolved_public_key:
        return PolicyVerificationResult(
            False,
            PolicyVerificationStatus.INVALID_SIGNATURE,
            "Issuer public key cannot be empty",
        )

    # 5. Algorithm validation
    if effective_sig_alg not in normalized_allowed:
        return PolicyVerificationResult(
            False,
            PolicyVerificationStatus.WRONG_ALGORITHM,
            f"Algorithm '{effective_sig_alg}' is not in allowed algorithms: {sorted(normalized_allowed)}",
        )

    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    if effective_sig_alg not in enabled_sigs:
        return PolicyVerificationResult(
            False,
            PolicyVerificationStatus.UNSUPPORTED_ALGORITHM,
            f"Algorithm '{effective_sig_alg}' is not enabled in liboqs.",
        )

    # 6. Cryptographic signature verification
    sig_verifier = None
    try:
        sig_verifier = oqs.Signature(effective_sig_alg)
        is_crypto_valid = sig_verifier.verify(raw_bytes, effective_sig, resolved_public_key)
        if not is_crypto_valid:
            return PolicyVerificationResult(
                False,
                PolicyVerificationStatus.INVALID_SIGNATURE,
                "Cryptographic signature verification returned False (tampered policy or signature mismatch).",
            )
    except Exception as exc:
        return PolicyVerificationResult(
            False,
            PolicyVerificationStatus.INVALID_SIGNATURE,
            f"Cryptographic verification error: {exc}",
        )
    finally:
        if sig_verifier is not None:
            sig_verifier.free()

    # 7. Monotonic version check (Anti-rollback)
    # Strictly evaluated AFTER signature verification proves authentic origin
    version = policy_dict["policy_version"]
    if last_seen_version is not None:
        if version < last_seen_version:
            return PolicyVerificationResult(
                False,
                PolicyVerificationStatus.STALE_POLICY,
                f"Policy version {version} is lower than last seen version {last_seen_version} (STALE_POLICY).",
            )
        elif version == last_seen_version and not allow_equal_version:
            return PolicyVerificationResult(
                False,
                PolicyVerificationStatus.STALE_POLICY,
                f"Policy version {version} equals last seen version {last_seen_version} under strict monotonic policy.",
            )

    return PolicyVerificationResult(
        True,
        PolicyVerificationStatus.VALID,
        "Policy signature, authority, structure, algorithm, and monotonic version successfully verified.",
    )


def verify_signed_envelope(
    envelope: Mapping[str, Any] | bytes | SignedPolicyEnvelope,
    issuer_public_key: Optional[bytes] = None,
    authority_registry: Optional[Mapping[str, bytes]] = None,
    allowed_algorithms: Container[str] | None = None,
    last_seen_version: int | None = None,
    allow_equal_version: bool = True,
) -> PolicyVerificationResult:
    """Verifies a signed policy envelope."""
    return verify_policy(
        policy_input=envelope,
        issuer_public_key=issuer_public_key,
        authority_registry=authority_registry,
        allowed_algorithms=allowed_algorithms,
        last_seen_version=last_seen_version,
        allow_equal_version=allow_equal_version,
    )
