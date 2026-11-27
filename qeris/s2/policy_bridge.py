"""
QERIS S2: Policy Bridge Module
Milestone: S1 + S2 + S3 Integration

Bridges S1's 5-field single-flow policy schema (signed with domain separation prefix
b"QERIS-POLICY-v1\\x00") and S2's multi-flow PolicyDocumentModel schema.

Enables the S2 Gateway and PolicyStore to consume, verify, and activate S1-formatted
signed policy envelopes while preserving S2's native verification pipeline.
"""
from __future__ import annotations

import os
from typing import Any, Container, Mapping, Optional, Union

from qeris.s2.config import (
    DEFAULT_ALLOWED_SIG_ALGS,
    DEFAULT_SIG_ALG,
    SecurityMode,
    SensitivityTier,
)
from qeris.s2.policy_schema import (
    FlowPolicyModel,
    PolicyDocumentModel,
    SignedPolicyEnvelopeModel,
)
from qeris.s2.policy_verifier import (
    PolicyVerificationResult as S2PolicyVerificationResult,
    PolicyVerificationStatus as S2PolicyVerificationStatus,
    verify_signed_policy as verify_s2_policy,
)

# S1 imports (available via conftest or direct package layout)
try:
    from qeris.policy.signed_policy import (
        DOMAIN_SEPARATION_LABEL as S1_DOMAIN_SEPARATION_LABEL,
        DEFAULT_ALLOWED_ALGORITHMS as S1_DEFAULT_ALLOWED_ALGS,
        PolicyVerificationResult as S1PolicyVerificationResult,
        PolicyVerificationStatus as S1PolicyVerificationStatus,
        SignedPolicyEnvelope as S1SignedPolicyEnvelope,
        sign_policy as s1_sign_policy,
        verify_policy as s1_verify_policy,
    )
    from qeris.policy.serialization import (
        CANONICAL_POLICY_FIELDS as S1_CANONICAL_FIELDS,
        serialize_policy_to_bytes as s1_serialize_policy,
    )
    _S1_POLICY_AVAILABLE = True
except ImportError:
    _S1_POLICY_AVAILABLE = False


MODE_TO_APPROVED_PROFILES: dict[str, list[str]] = {
    "CLASSICAL": ["CLASSICAL_ECDH_AESGCM"],
    "HYBRID":    ["HYBRID_X25519_MLKEM_AESGCM"],
    "PQC":       ["PQC_MLKEM512_AESGCM", "PQC_MLKEM768_AESGCM"],
    "PQ":        ["PQC_MLKEM512_AESGCM", "PQC_MLKEM768_AESGCM"],
}


def is_s1_envelope(data: Any) -> bool:
    """Detect whether data represents an S1 5-field signed policy envelope."""
    if not _S1_POLICY_AVAILABLE:
        return False
    if isinstance(data, S1SignedPolicyEnvelope):
        return True
    if isinstance(data, Mapping) and "policy" in data and "signature" in data:
        policy = data["policy"]
        if isinstance(policy, Mapping):
            # S1 policies have flow_id and sensitivity directly in the policy mapping
            return "flow_id" in policy and "sensitivity" in policy and "minimum_mode" in policy
    return False


def s1_dict_to_s2_policy_document(s1_policy: Mapping[str, Any]) -> PolicyDocumentModel:
    """
    Converts S1's 5-field policy mapping:
      {flow_id, sensitivity, minimum_mode, policy_version, authority_id}
    into an S2 PolicyDocumentModel.
    """
    flow_id = str(s1_policy["flow_id"])
    min_mode_raw = str(s1_policy["minimum_mode"]).upper()
    sensitivity_raw = str(s1_policy["sensitivity"]).upper()
    version = int(s1_policy["policy_version"])
    authority = str(s1_policy["authority_id"])

    # Normalization
    min_mode_key = "PQC" if min_mode_raw in ("PQ", "PQC") else min_mode_raw
    sec_mode = SecurityMode(min_mode_key)
    sens_tier = SensitivityTier(sensitivity_raw)
    approved_profiles = list(MODE_TO_APPROVED_PROFILES.get(min_mode_key, [min_mode_key]))

    flow_model = FlowPolicyModel(
        flow_id=flow_id,
        device_scope=["*"],
        sensitivity=sens_tier,
        minimum_mode=sec_mode,
        approved_security_profiles=approved_profiles,
    )

    return PolicyDocumentModel(
        authority_id=authority,
        policy_version=version,
        policies={flow_id: flow_model},
    )


def verify_s1_policy_envelope(
    envelope_data: Union[dict[str, Any], S1SignedPolicyEnvelope],
    trusted_authorities: Mapping[str, Any],
    allowed_algorithms: Optional[Container[str]] = None,
    last_seen_version: Optional[int] = None,
) -> S1PolicyVerificationResult:
    """
    Verifies an S1 signed policy envelope using S1's domain separation prefix
    (b"QERIS-POLICY-v1\\x00") and ML-DSA-65 verification.
    """
    if not _S1_POLICY_AVAILABLE:
        raise RuntimeError("S1 policy module is not available on path")

    # Adapt trusted_authorities format if needed (handle raw bytes or hex strings)
    adapted_authorities: dict[str, bytes] = {}
    for auth_id, key_obj in trusted_authorities.items():
        if isinstance(key_obj, str):
            try:
                adapted_authorities[auth_id] = bytes.fromhex(key_obj.strip())
            except ValueError:
                # If PEM or other string
                adapted_authorities[auth_id] = key_obj.encode("utf-8")
        elif isinstance(key_obj, (bytes, bytearray)):
            adapted_authorities[auth_id] = bytes(key_obj)
        elif hasattr(key_obj, "public_bytes_raw"):
            # cryptography MLDSA65PublicKey
            adapted_authorities[auth_id] = key_obj.public_bytes_raw()
        else:
            adapted_authorities[auth_id] = key_obj

    return s1_verify_policy(
        policy_input=envelope_data,
        authority_registry=adapted_authorities,
        allowed_algorithms=allowed_algorithms or S1_DEFAULT_ALLOWED_ALGS,
        last_seen_version=last_seen_version,
    )


def verify_unified_policy(
    envelope_data: Union[dict[str, Any], SignedPolicyEnvelopeModel, Any],
    trusted_authorities: Mapping[str, Any],
    allowed_algorithms: Container[str] = DEFAULT_ALLOWED_SIG_ALGS,
) -> S2PolicyVerificationResult:
    """
    Unified verifier entrypoint:
    Dispatches to S1 domain-separated verification if an S1 5-field envelope is given,
    or S2 canonical verification if an S2 PolicyDocumentModel envelope is given.

    Returns an S2 PolicyVerificationResult for consistent consumption by S2 PolicyStore.
    """
    if is_s1_envelope(envelope_data):
        s1_result = verify_s1_policy_envelope(
            envelope_data=envelope_data,
            trusted_authorities=trusted_authorities,
            allowed_algorithms=allowed_algorithms,
        )

        status_mapping = {
            S1PolicyVerificationStatus.VALID: S2PolicyVerificationStatus.VALID,
            S1PolicyVerificationStatus.INVALID_STRUCTURE: S2PolicyVerificationStatus.INVALID_STRUCTURE,
            S1PolicyVerificationStatus.UNTRUSTED_AUTHORITY: S2PolicyVerificationStatus.UNTRUSTED_AUTHORITY,
            S1PolicyVerificationStatus.WRONG_ALGORITHM: S2PolicyVerificationStatus.WRONG_ALGORITHM,
            S1PolicyVerificationStatus.UNSUPPORTED_ALGORITHM: S2PolicyVerificationStatus.WRONG_ALGORITHM,
            S1PolicyVerificationStatus.INVALID_SIGNATURE: S2PolicyVerificationStatus.INVALID_SIGNATURE,
            S1PolicyVerificationStatus.STALE_POLICY: S2PolicyVerificationStatus.STALE_VERSION,
        }
        s2_status = status_mapping.get(s1_result.status, S2PolicyVerificationStatus.INVALID_STRUCTURE)

        s2_envelope = None
        if s1_result.is_valid:
            if isinstance(envelope_data, S1SignedPolicyEnvelope):
                p_dict = envelope_data.policy
                sig_hex = envelope_data.signature.hex() if isinstance(envelope_data.signature, bytes) else str(envelope_data.signature)
            else:
                p_dict = envelope_data["policy"]
                raw_sig = envelope_data["signature"]
                sig_hex = raw_sig.hex() if isinstance(raw_sig, bytes) else str(raw_sig)

            doc_model = s1_dict_to_s2_policy_document(p_dict)
            s2_envelope = SignedPolicyEnvelopeModel(
                policy=doc_model,
                policy_digest=doc_model.compute_digest(),
                sig_alg=DEFAULT_SIG_ALG,
                signature=sig_hex,
            )

        return S2PolicyVerificationResult(
            is_valid=s1_result.is_valid,
            status=s2_status,
            message=f"[S1-Bridge] {s1_result.message}",
            envelope=s2_envelope,
        )

    # Standard S2 path
    return verify_s2_policy(
        envelope_data=envelope_data,
        trusted_authorities=trusted_authorities,
        allowed_algorithms=allowed_algorithms,
    )
