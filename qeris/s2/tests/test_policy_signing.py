"""
Unit Tests for ML-DSA-65 Policy Signing and Verification
"""
import pytest
from qeris.s2.crypto_engine import generate_authority_keypair
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel, SignedPolicyEnvelopeModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_verifier import PolicyVerificationStatus, verify_signed_policy

def make_sample_doc(authority_id="AUTH-01", version=1):
    return PolicyDocumentModel(
        authority_id=authority_id,
        policy_version=version,
        policies={
            "flow_crit": FlowPolicyModel(
                flow_id="flow_crit",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
            "flow_low": FlowPolicyModel(
                flow_id="flow_low",
                device_scope=["dev1", "dev2"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=["CLASSICAL_ECDH_AESGCM", "PQC_MLKEM512_AESGCM"],
            ),
        },
    )

def test_valid_signed_policy_accepted(authority_keys):
    doc = make_sample_doc(authority_keys["authority_id"], 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    res = verify_signed_policy(envelope, trusted)
    assert res.is_valid is True
    assert res.status == PolicyVerificationStatus.VALID
    assert res.envelope is not None

def test_tampered_policy_content_rejected(authority_keys):
    doc = make_sample_doc(authority_keys["authority_id"], 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Tamper with policy version inside envelope without resigning
    env_dict = envelope.model_dump()
    env_dict["policy"]["policy_version"] = 999

    res = verify_signed_policy(env_dict, trusted)
    assert res.is_valid is False
    # Digest mismatch or invalid signature
    assert res.status in (PolicyVerificationStatus.DIGEST_MISMATCH, PolicyVerificationStatus.INVALID_SIGNATURE)

def test_tampered_signature_rejected(authority_keys):
    doc = make_sample_doc(authority_keys["authority_id"], 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env_dict = envelope.model_dump()
    # Flip bytes in signature hex
    sig = list(env_dict["signature"])
    sig[10] = "0" if sig[10] != "0" else "1"
    env_dict["signature"] = "".join(sig)

    res = verify_signed_policy(env_dict, trusted)
    assert res.is_valid is False
    assert res.status == PolicyVerificationStatus.INVALID_SIGNATURE

def test_unknown_authority_rejected(authority_keys):
    doc = make_sample_doc("UNKNOWN-ATTACKER-ID", 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    res = verify_signed_policy(envelope, trusted)
    assert res.is_valid is False
    assert res.status == PolicyVerificationStatus.UNTRUSTED_AUTHORITY

def test_wrong_authority_key_rejected(authority_keys):
    doc = make_sample_doc(authority_keys["authority_id"], 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])

    # Provide a different valid ML-DSA-65 key under the same authority_id
    _, different_pub_pem, _ = generate_authority_keypair()
    trusted = {authority_keys["authority_id"]: different_pub_pem}

    res = verify_signed_policy(envelope, trusted)
    assert res.is_valid is False
    assert res.status == PolicyVerificationStatus.INVALID_SIGNATURE

def test_disallowed_algorithm_rejected(authority_keys):
    doc = make_sample_doc(authority_keys["authority_id"], 1)
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env_dict = envelope.model_dump()
    env_dict["sig_alg"] = "RSA-PKCS1v15"

    res = verify_signed_policy(env_dict, trusted)
    assert res.is_valid is False
    assert res.status == PolicyVerificationStatus.WRONG_ALGORITHM
