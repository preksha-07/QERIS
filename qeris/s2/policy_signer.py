"""
QERIS S2: Policy Signer Utility

Signs policy documents using FIPS 204 ML-DSA-65 private keys
and outputs canonical signed policy envelopes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Union

from qeris.s2.config import DEFAULT_SIG_ALG
from qeris.s2.crypto_engine import sign_canonical_policy
from qeris.s2.policy_schema import PolicyDocumentModel, SignedPolicyEnvelopeModel


def sign_policy_document(
    policy_doc: Union[dict[str, Any], PolicyDocumentModel],
    private_key_material: Union[bytes, str],
    sig_alg: str = DEFAULT_SIG_ALG,
) -> SignedPolicyEnvelopeModel:
    """
    Canonically serializes policy document, computes digest, signs with ML-DSA-65,
    and returns a verified SignedPolicyEnvelopeModel.
    """
    if not isinstance(policy_doc, PolicyDocumentModel):
        doc = PolicyDocumentModel.model_validate(policy_doc)
    else:
        doc = policy_doc

    canonical_bytes = doc.canonical_bytes()
    digest = doc.compute_digest()
    sig_hex = sign_canonical_policy(canonical_bytes, private_key_material)

    return SignedPolicyEnvelopeModel(
        policy=doc,
        policy_digest=digest,
        sig_alg=sig_alg,
        signature=sig_hex,
    )


def export_signed_policy_file(envelope: SignedPolicyEnvelopeModel, output_path: Union[str, Path]) -> None:
    """Writes signed policy envelope to JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(envelope.to_export_dict(), f, indent=2)
