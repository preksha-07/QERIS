"""
Unit Tests for Session Context Management and DEC-4 Policy Epoch Guard
"""
import pytest
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.session_manager import SessionManager, SessionState

def make_envelope(authority_id, version, priv_pem, approved_profiles):
    doc = PolicyDocumentModel(
        authority_id=authority_id,
        policy_version=version,
        policies={
            "flow_monitored": FlowPolicyModel(
                flow_id="flow_monitored",
                device_scope=["*"],
                sensitivity="HIGH",
                minimum_mode="HYBRID",
                approved_security_profiles=approved_profiles,
            )
        },
    )
    return sign_policy_document(doc, priv_pem)

def test_session_lifecycle_and_creation(authority_keys):
    sm = SessionManager()
    env = make_envelope(
        authority_keys["authority_id"],
        1,
        authority_keys["priv_pem"],
        ["HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"],
    )

    ctx = sm.create_session(
        device_id="dev1",
        flow_id="flow_monitored",
        policy_envelope=env,
        negotiated_profile="HYBRID_X25519_MLKEM_AESGCM",
        negotiated_mode="HYBRID",
        session_key=b"K" * 32,
    )

    assert ctx.session_id is not None
    assert ctx.state == SessionState.ACTIVE
    assert ctx.policy_version == 1
    assert ctx.policy_digest == env.policy_digest

    # Validation in same epoch succeeds
    valid, msg = sm.validate_and_rebind_session(ctx, env)
    assert valid is True
    assert "CURRENT_EPOCH" in msg

def test_dec4_policy_update_rebinds_when_profile_still_approved(authority_keys):
    sm = SessionManager()
    # Policy V1: approves HYBRID and PQC
    env_v1 = make_envelope(
        authority_keys["authority_id"],
        1,
        authority_keys["priv_pem"],
        ["HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"],
    )
    ctx = sm.create_session(
        device_id="dev1",
        flow_id="flow_monitored",
        policy_envelope=env_v1,
        negotiated_profile="PQC_MLKEM512_AESGCM",
        negotiated_mode="PQC",
        session_key=b"K" * 32,
    )

    # Policy V2: advances version, but PQC is still approved
    env_v2 = make_envelope(
        authority_keys["authority_id"],
        2,
        authority_keys["priv_pem"],
        ["PQC_MLKEM512_AESGCM", "PQC_MLKEM768_AESGCM"],
    )
    sm.advance_epoch()

    valid, msg = sm.validate_and_rebind_session(ctx, env_v2)
    assert valid is True
    assert "REBOUND" in msg
    assert ctx.policy_version == 2
    assert ctx.policy_digest == env_v2.policy_digest
    assert ctx.state == SessionState.ACTIVE

def test_dec4_policy_update_invalidates_session_when_profile_disallowed(authority_keys):
    sm = SessionManager()
    # Policy V1: approves HYBRID and PQC. Session negotiated HYBRID.
    env_v1 = make_envelope(
        authority_keys["authority_id"],
        1,
        authority_keys["priv_pem"],
        ["HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"],
    )
    ctx = sm.create_session(
        device_id="dev1",
        flow_id="flow_monitored",
        policy_envelope=env_v1,
        negotiated_profile="HYBRID_X25519_MLKEM_AESGCM",
        negotiated_mode="HYBRID",
        session_key=b"K" * 32,
    )

    # Policy V2: Tightens policy to PQC ONLY! HYBRID is no longer approved!
    env_v2 = make_envelope(
        authority_keys["authority_id"],
        2,
        authority_keys["priv_pem"],
        ["PQC_MLKEM512_AESGCM"],
    )
    sm.advance_epoch()

    # DEC-4 Guard must detect that the active session is below the newly activated floor!
    valid, msg = sm.validate_and_rebind_session(ctx, env_v2)
    assert valid is False
    assert ctx.state == SessionState.STALE
    assert "no longer approved" in msg
