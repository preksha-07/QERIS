"""
QERIS S2: Policy Verifier

Verifies signed policy envelopes against trusted authority public keys.
Performs strict structural, digest, algorithmic, and cryptographic verification
prior to any state-machine or version store processing.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Container, Mapping, Optional

from qeris.s2.canonical_json import canonical_encode, compute_policy_digest
from qeris.s2.config import DEFAULT_ALLOWED_SIG_ALGS
from qeris.s2.crypto_engine import verify_policy_signature
from qeris.s2.policy_schema import PolicyDocumentModel, SignedPolicyEnvelopeModel


class PolicyVerificationStatus(str, Enum):
    VALID                  = "VALID"
    INVALID_STRUCTURE      = "INVALID_STRUCTURE"
    UNTRUSTED_AUTHORITY    = "UNTRUSTED_AUTHORITY"
    WRONG_ALGORITHM        = "WRONG_ALGORITHM"
    DIGEST_MISMATCH        = "DIGEST_MISMATCH"
    INVALID_SIGNATURE      = "INVALID_SIGNATURE"
    STALE_VERSION          = "STALE_VERSION"


class PolicyVerificationResult:
    def __init__(self, is_valid: bool, status: PolicyVerificationStatus, message: str, envelope: Optional[SignedPolicyEnvelopeModel] = None):
        self.is_valid = is_valid
        self.status = status
        self.message = message
        self.envelope = envelope

    def __bool__(self) -> bool:
        return self.is_valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "status": self.status.value,
            "message": self.message,
            "policy_version": self.envelope.policy.policy_version if self.envelope else None,
            "authority_id": self.envelope.policy.authority_id if self.envelope else None,
        }


def verify_signed_policy(
    envelope_data: Union[dict[str, Any], SignedPolicyEnvelopeModel],
    trusted_authorities: Mapping[str, Any],
    allowed_algorithms: Container[str] = DEFAULT_ALLOWED_SIG_ALGS,
) -> PolicyVerificationResult:
    """
    Verifies a signed policy envelope strictly before any anti-rollback or activation logic.

    Checks:
    1. Structure and required schema fields.
    2. Authority resolution against trusted authority public keys.
    3. Algorithm allowlisting (pinned to ML-DSA-65).
    4. Deterministic canonical encoding and SHA-256 digest match.
    5. Cryptographic signature verification with pinned authority key.
    """
    # 1. Structure validation
    try:
        if isinstance(envelope_data, SignedPolicyEnvelopeModel):
            envelope = envelope_data
        else:
            envelope = SignedPolicyEnvelopeModel.model_validate(envelope_data)
    except Exception as exc:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_STRUCTURE,
            message=f"Policy envelope schema validation failed: {exc}",
        )

    # 2. Authority trust validation
    authority_id = envelope.policy.authority_id
    if authority_id not in trusted_authorities:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.UNTRUSTED_AUTHORITY,
            message=f"Authority '{authority_id}' is not in configured trusted authority set",
        )
    authority_pub_key = trusted_authorities[authority_id]

    # 3. Algorithm allowlisting
    if envelope.sig_alg not in allowed_algorithms:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.WRONG_ALGORITHM,
            message=f"Signature algorithm '{envelope.sig_alg}' is not in allowed list: {allowed_algorithms}",
        )

    # 4. Canonical digest verification
    canonical_bytes = envelope.policy.canonical_bytes()
    expected_digest = envelope.policy.compute_digest()
    if envelope.policy_digest.lower() != expected_digest.lower():
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.DIGEST_MISMATCH,
            message=f"Policy digest mismatch: envelope claimed '{envelope.policy_digest}', computed '{expected_digest}'",
        )

    # 5. Cryptographic ML-DSA-65 signature verification
    sig_ok = verify_policy_signature(canonical_bytes, envelope.signature, authority_pub_key)
    if not sig_ok:
        return PolicyVerificationResult(
            is_valid=False,
            status=PolicyVerificationStatus.INVALID_SIGNATURE,
            message="Cryptographic signature verification failed (tampered content or invalid signature)",
        )

    return PolicyVerificationResult(
        is_valid=True,
        status=PolicyVerificationStatus.VALID,
        message="Policy signature, digest, and structure verified successfully",
        envelope=envelope,
    )
