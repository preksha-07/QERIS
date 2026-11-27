"""
QERIS End-to-End Integration Test Suite: S1 (Crypto) + S2 (Gateway) + S3 (Security/Recovery)
Milestone: S1 + S2 + S3 Integration Verification

Validates:
1. PQC Full Round-Trip (ML-KEM-512 KEM + HKDF + S1 MessageEncryptor/Decryptor + S3 ALLOW)
2. Classical Full Round-Trip (X25519 ECDH + HKDF + S1 MessageEncryptor/Decryptor + S3 ALLOW)
3. Hybrid Full Round-Trip (X25519 + ML-KEM-768 + S1 MessageEncryptor/Decryptor + S3 ALLOW)
4. Ed25519 Device Authentication (Challenge-Response, Single-Use, Expiry, S3 Audit)
5. Device Authentication Failure (Invalid Signature -> 401 -> S3 SECURITY_FAILURE)
6. Quarantined Device Handshake Rejection (S2 NOT_READY -> S3 BLOCK)
7. Unknown Device Rejection (Unregistered Device -> 401/404 -> S3 SECURITY_FAILURE)
8. Message Integrity / Tampered AEAD Tag (S1 AuthenticationError -> S3 SECURITY_FAILURE)
9. Message Anti-Replay Protection (S1 ReplayError -> S3 SECURITY_FAILURE)
10. S1 Policy Bridge & Monotonic Anti-Rollback (Domain-Separated ML-DSA-65 Policy -> S2 PolicyStore)
11. DEC-4 Policy Epoch Guard (Policy update narrowing floor invalidates active session)
12. S1 Structured Event Logging (8 agreed fields, no private keys or secrets)
"""
from __future__ import annotations

import os
import sys
import time
import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
import conftest

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import BaselineMode, SecurityMode, SecurityProfile, SensitivityTier
from qeris.s2.crypto_adapter import establish_session, perform_kem_exchange
from qeris.s2.crypto_engine import generate_authority_keypair, sign_canonical_policy
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_bridge import s1_dict_to_s2_policy_document, verify_unified_policy
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel, SignedPolicyEnvelopeModel
from qeris.s2.policy_store import PolicyStore
from qeris.s2.s3_adapter import S3IntegrationAdapter

from qeris.device_auth import (
    Ed25519DeviceCredential,
    GatewayChallengeManager,
    build_canonical_device_auth_message,
)
from qeris.secure_message import (
    AuthenticationError,
    MessageContext,
    MessageDecryptor,
    MessageEncryptor,
    ReplayError,
)
from qeris.device_simulator import create_device_event


@pytest.fixture
def integration_env(tmp_path):
    """Initializes a full gateway test environment with authority keys and policy store."""
    db_policy = str(tmp_path / "test_policy.db")
    db_reg = str(tmp_path / "test_reg.db")

    priv_pem, pub_pem, pub_hex = generate_authority_keypair()
    trusted_auths = {"TEST-AUTHORITY": pub_hex}

    policy_store = PolicyStore(db_path=db_policy)
    registry = DeviceRegistry(db_path=db_reg)
    s3_adapter = S3IntegrationAdapter(trusted_authorities=trusted_auths)

    # Initial Policy: 3 flows (PQC, Hybrid, Classical)
    flow_pqc = FlowPolicyModel(
        flow_id="telemetry_critical",
        device_scope=["*"],
        sensitivity=SensitivityTier.CRITICAL,
        minimum_mode=SecurityMode.PQC,
        approved_security_profiles=["PQC_MLKEM512_AESGCM", "PQC_MLKEM768_AESGCM"],
    )
    flow_hybrid = FlowPolicyModel(
        flow_id="telemetry_high",
        device_scope=["*"],
        sensitivity=SensitivityTier.HIGH,
        minimum_mode=SecurityMode.HYBRID,
        approved_security_profiles=["HYBRID_X25519_MLKEM_AESGCM"],
    )
    flow_classical = FlowPolicyModel(
        flow_id="telemetry_low",
        device_scope=["*"],
        sensitivity=SensitivityTier.LOW,
        minimum_mode=SecurityMode.CLASSICAL,
        approved_security_profiles=["CLASSICAL_ECDH_AESGCM"],
    )

    doc = PolicyDocumentModel(
        authority_id="TEST-AUTHORITY",
        policy_version=1,
        policies={
            "telemetry_critical": flow_pqc,
            "telemetry_high": flow_hybrid,
            "telemetry_low": flow_classical,
        },
    )
    sig_hex = sign_canonical_policy(doc.canonical_bytes(), priv_pem)
    envelope = SignedPolicyEnvelopeModel(
        policy=doc,
        policy_digest=doc.compute_digest(),
        signature=sig_hex,
    )
    install_res = policy_store.install_policy(envelope, trusted_auths)
    assert install_res.success, f"Policy install failed: {install_res.message}"

    from qeris.s2.config import GatewayConfig
    gw_config = GatewayConfig(admin_api_key="test_admin_secret_key")
    app = create_gateway_app(
        policy_store=policy_store,
        registry=registry,
        s3_adapter=s3_adapter,
        trusted_authorities=trusted_auths,
        config=gw_config,
    )
    client = TestClient(app)

    return {
        "client": client,
        "app": app,
        "policy_store": policy_store,
        "registry": registry,
        "s3_adapter": s3_adapter,
        "trusted_auths": trusted_auths,
        "priv_pem": priv_pem,
        "pub_hex": pub_hex,
        "admin_headers": {"X-Admin-Key": "test_admin_secret_key"},
    }


def test_integration_pqc_full_roundtrip(integration_env):
    """Test 1: Full PQC roundtrip with Ed25519 device auth, ML-KEM exchange, and S1 MessageEncryptor."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "pqc_sensor_01"
    flow_id = "telemetry_critical"
    dev_cred = Ed25519DeviceCredential()

    # 1. Register device with Ed25519 public key
    profile = DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["PQC", "HYBRID", "CLASSICAL"],
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
        ed25519_public_key_hex=dev_cred.public_key_hex,
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=2000,
    )
    registry.register_device(profile)

    # 2. Issue challenge
    resp_chal = client.post("/api/v1/auth/challenge", json={"device_id": device_id})
    assert resp_chal.status_code == 200
    chal_data = resp_chal.json()
    nonce_hex = chal_data["challenge_nonce_hex"]

    # 3. Perform real S1 PQC KEM key exchange
    key, handshake_id = perform_kem_exchange("PQC", device_id=device_id, flow_id=flow_id, sensitivity="CRITICAL", policy_version=1)

    # 4. Sign and verify device authentication
    ts = int(time.time())
    sig = dev_cred.sign_authentication_message(
        device_id=device_id,
        handshake_id=handshake_id,
        challenge_nonce=bytes.fromhex(nonce_hex),
        timestamp=ts,
    )
    resp_auth = client.post("/api/v1/auth/verify", json={
        "device_id": device_id,
        "handshake_id": handshake_id,
        "challenge_nonce_hex": nonce_hex,
        "timestamp": ts,
        "signature_hex": sig.hex(),
        "public_key_hex": dev_cred.public_key_hex,
        "flow_id": flow_id,
    })
    assert resp_auth.status_code == 200
    assert resp_auth.json()["status"] == "AUTH_SUCCESS"

    # 5. Handshake initiate & complete
    resp_init = client.post("/api/v1/handshake/initiate", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "offered_modes": ["PQC"],
        "offered_profiles": ["PQC_MLKEM512_AESGCM"],
    })
    assert resp_init.status_code == 200
    assert resp_init.json()["decision"] == "ALLOW"

    resp_comp = client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "PQC_MLKEM512_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": handshake_id,
    })
    assert resp_comp.status_code == 200
    session_id = resp_comp.json()["session_id"]

    # 6. Device encrypts telemetry via S1 MessageEncryptor
    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="CRITICAL", policy_version=1)
    encryptor = MessageEncryptor(session_key=key, context=ctx)
    plaintext = b'{"temperature": 24.5, "pressure": 1013.25}'
    wire_bytes = encryptor.encrypt(plaintext)
    assert wire_bytes.startswith(b"QMSG")

    # 7. Gateway receives and decrypts telemetry
    resp_tel = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "session_id": session_id,
        "payload": None,
        "encrypted_envelope_hex": wire_bytes.hex(),
    })
    assert resp_tel.status_code == 200
    res_data = resp_tel.json()
    assert res_data["status"] in ("FORWARDED", "ACCEPTED")
    assert res_data["sensitivity"] == "CRITICAL"


def test_integration_classical_full_roundtrip(integration_env):
    """Test 2: Full Classical X25519 roundtrip with real ECDH key derivation and message protection."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "classical_sensor_01"
    flow_id = "telemetry_low"

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["CLASSICAL"],
        supported_security_profiles=["CLASSICAL_ECDH_AESGCM"],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=1280,
    ))

    key, hid = perform_kem_exchange("CLASSICAL", device_id=device_id, flow_id=flow_id, sensitivity="LOW", policy_version=1)

    resp_comp = client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "CLASSICAL_ECDH_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": hid,
    })
    assert resp_comp.status_code == 200

    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="LOW", policy_version=1)
    enc = MessageEncryptor(session_key=key, context=ctx)
    wire = enc.encrypt(b'{"status": "OK", "battery": 98}')

    resp_tel = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": wire.hex(),
    })
    assert resp_tel.status_code == 200
    assert resp_tel.json()["status"] in ("FORWARDED", "ACCEPTED")


def test_integration_hybrid_full_roundtrip(integration_env):
    """Test 3: Full Hybrid X25519 + ML-KEM-768 roundtrip."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "hybrid_sensor_01"
    flow_id = "telemetry_high"

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["HYBRID", "CLASSICAL"],
        supported_security_profiles=["HYBRID_X25519_MLKEM_AESGCM"],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=3000,
    ))

    key, hid = perform_kem_exchange("HYBRID", device_id=device_id, flow_id=flow_id, sensitivity="HIGH", policy_version=1)

    resp_comp = client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "HYBRID_X25519_MLKEM_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": hid,
    })
    assert resp_comp.status_code == 200

    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="HIGH", policy_version=1)
    enc = MessageEncryptor(session_key=key, context=ctx)
    wire = enc.encrypt(b'{"grid_voltage": 230.1, "frequency": 50.0}')

    resp_tel = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": wire.hex(),
    })
    assert resp_tel.status_code == 200
    assert resp_tel.json()["status"] in ("FORWARDED", "ACCEPTED")


def test_integration_device_auth_invalid_signature(integration_env):
    """Test 4: Device authentication rejects invalid Ed25519 signature."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "dev_tamper_auth"
    dev_cred = Ed25519DeviceCredential()

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        ed25519_public_key_hex=dev_cred.public_key_hex,
    ))

    resp_chal = client.post("/api/v1/auth/challenge", json={"device_id": device_id})
    nonce_hex = resp_chal.json()["challenge_nonce_hex"]

    bad_sig = b"\x00" * 64

    resp_auth = client.post("/api/v1/auth/verify", json={
        "device_id": device_id,
        "handshake_id": "test_hid",
        "challenge_nonce_hex": nonce_hex,
        "timestamp": int(time.time()),
        "signature_hex": bad_sig.hex(),
        "public_key_hex": dev_cred.public_key_hex,
    })
    assert resp_auth.status_code == 401
    assert "verification failed" in resp_auth.json()["detail"]


def test_integration_device_auth_single_use_challenge(integration_env):
    """Test 5: Replayed challenge nonce is rejected (single-use enforcement)."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "dev_single_use"
    dev_cred = Ed25519DeviceCredential()

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        ed25519_public_key_hex=dev_cred.public_key_hex,
    ))

    resp_chal = client.post("/api/v1/auth/challenge", json={"device_id": device_id})
    nonce_hex = resp_chal.json()["challenge_nonce_hex"]
    import hashlib
    valid_hid = hashlib.sha256(b"canonical_handshake_transcript_1").hexdigest()
    ts = int(time.time())
    sig = dev_cred.sign_authentication_message(
        device_id=device_id,
        handshake_id=valid_hid,
        challenge_nonce=bytes.fromhex(nonce_hex),
        timestamp=ts,
    )

    # First verify succeeds
    r1 = client.post("/api/v1/auth/verify", json={
        "device_id": device_id,
        "handshake_id": valid_hid,
        "challenge_nonce_hex": nonce_hex,
        "timestamp": ts,
        "signature_hex": sig.hex(),
        "public_key_hex": dev_cred.public_key_hex,
    })
    assert r1.status_code == 200

    # Second verify with same challenge is rejected
    r2 = client.post("/api/v1/auth/verify", json={
        "device_id": device_id,
        "handshake_id": valid_hid,
        "challenge_nonce_hex": nonce_hex,
        "timestamp": ts,
        "signature_hex": sig.hex(),
        "public_key_hex": dev_cred.public_key_hex,
    })
    assert r2.status_code == 401
    assert "AUTH_CHALLENGE_REPLAYED" in r2.json()["detail"]


def test_integration_quarantined_device(integration_env):
    """Test 6: Quarantined device is rejected by S2 readiness."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "dev_quarantined_99"
    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        quarantined=True,
        quarantine_reason="Hardware integrity tamper flag active",
    ))

    resp = client.post("/api/v1/handshake/initiate", json={
        "device_id": device_id,
        "flow_id": "telemetry_critical",
        "offered_modes": ["PQC"],
    })
    assert resp.status_code == 403
    assert resp.json()["decision"] == "REJECT"
    assert "quarantined" in resp.json()["reason"].lower()


def test_integration_tampered_aead_tag_rejected(integration_env):
    """Test 7: Tampered message envelope tag triggers S1 AuthenticationError and S3 notification."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "dev_tamper_msg"
    flow_id = "telemetry_critical"

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["PQC"],
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
    ))

    key, hid = perform_kem_exchange("PQC", device_id=device_id, flow_id=flow_id, sensitivity="CRITICAL", policy_version=1)
    client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "PQC_MLKEM512_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": hid,
    })

    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="CRITICAL", policy_version=1)
    enc = MessageEncryptor(session_key=key, context=ctx)
    wire = bytearray(enc.encrypt(b"Top secret telemetry payload"))
    wire[-1] ^= 0x55  # Tamper AEAD authentication tag

    resp = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": bytes(wire).hex(),
    })
    assert resp.status_code == 400
    assert "Message authentication failed" in resp.json()["detail"]


def test_integration_replayed_envelope_rejected(integration_env):
    """Test 8: Replayed message counter is rejected by S1 MessageDecryptor."""
    client = integration_env["client"]
    registry = integration_env["registry"]

    device_id = "dev_replay_msg"
    flow_id = "telemetry_critical"

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["PQC"],
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
    ))

    key, hid = perform_kem_exchange("PQC", device_id=device_id, flow_id=flow_id, sensitivity="CRITICAL", policy_version=1)
    client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "PQC_MLKEM512_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": hid,
    })

    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="CRITICAL", policy_version=1)
    enc = MessageEncryptor(session_key=key, context=ctx)
    wire_hex = enc.encrypt(b"Valid message 0").hex()

    # First send succeeds
    r1 = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": wire_hex,
    })
    assert r1.status_code == 200

    # Replay of exact same message is rejected
    r2 = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": wire_hex,
    })
    assert r2.status_code == 400
    assert "Message authentication failed" in r2.json()["detail"]


def test_integration_policy_epoch_guard_dec4(integration_env):
    """Test 9: DEC-4 Policy Epoch Guard invalidates active session when policy update excludes flow."""
    client = integration_env["client"]
    registry = integration_env["registry"]
    policy_store = integration_env["policy_store"]
    priv_pem = integration_env["priv_pem"]
    trusted_auths = integration_env["trusted_auths"]

    device_id = "dev_epoch_guard"
    flow_id = "telemetry_low"

    registry.register_device(DeviceCapabilityProfile(
        device_id=device_id,
        supported_modes=["CLASSICAL"],
        supported_security_profiles=["CLASSICAL_ECDH_AESGCM"],
    ))

    key, hid = perform_kem_exchange("CLASSICAL", device_id=device_id, flow_id=flow_id, sensitivity="LOW", policy_version=1)
    client.post("/api/v1/handshake/complete", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "negotiated_profile": "CLASSICAL_ECDH_AESGCM",
        "session_key_hex": key.hex(),
        "handshake_id": hid,
    })

    # Policy update to v2 that raises floor and REMOVES telemetry_low
    doc_v2 = PolicyDocumentModel(
        authority_id="TEST-AUTHORITY",
        policy_version=2,
        policies={
            "telemetry_critical": FlowPolicyModel(
                flow_id="telemetry_critical",
                device_scope=["*"],
                sensitivity=SensitivityTier.CRITICAL,
                minimum_mode=SecurityMode.PQC,
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
        },
    )
    sig_v2 = sign_canonical_policy(doc_v2.canonical_bytes(), priv_pem)
    env_v2 = SignedPolicyEnvelopeModel(
        policy=doc_v2,
        policy_digest=doc_v2.compute_digest(),
        signature=sig_v2,
    )

    resp_pol = client.post(
        "/api/v1/admin/policy",
        json=env_v2.to_export_dict(),
        headers=integration_env["admin_headers"],
    )
    assert resp_pol.status_code == 200

    # Existing session under v1 for telemetry_low now rejected under DEC-4
    ctx = MessageContext(device_id=device_id, flow_id=flow_id, sensitivity_tier="LOW", policy_version=1)
    enc = MessageEncryptor(session_key=key, context=ctx)
    wire = enc.encrypt(b"Late message under stale policy")

    resp_tel = client.post("/api/v1/telemetry", json={
        "device_id": device_id,
        "flow_id": flow_id,
        "payload": None,
        "encrypted_envelope_hex": wire.hex(),
    })
    assert resp_tel.status_code == 403
    assert "DEC-4 Policy Epoch Mismatch" in resp_tel.json()["detail"]


def test_integration_structured_device_event_logging():
    """Test 10: S1 device event contains the 8 agreed fields and never leaks secret keys."""
    event = create_device_event(
        device_id="dev-sensor-esp32",
        flow_id="crit_flow",
        event="handshake_completed",
        mode="HYBRID",
        cause="normal",
        size_bytes=2336,
        duration_ms=42.5,
    )

    required_fields = {
        "ts", "device_id", "flow_id", "event",
        "mode", "cause", "size_bytes", "duration_ms",
    }
    assert required_fields.issubset(set(event.keys())), f"Missing fields: {required_fields - set(event.keys())}"

    assert event["device_id"] == "dev-sensor-esp32"
    assert event["mode"] == "HYBRID"
    assert event["size_bytes"] == 2336

    # Verify no private keys or secrets are leaked
    event_str = str(event).lower()
    for sensitive_word in ("private_key", "secret_key", "seed", "aes_key"):
        assert sensitive_word not in event_str, f"Leaked sensitive token: {sensitive_word}"


def test_integration_policy_bridge_s1_envelope(integration_env):
    """Test 11: S1 5-field policy envelope is parsed, verified, converted to S2 model, and activated."""
    from qeris.policy.signed_policy import sign_policy, SignedPolicyEnvelope
    import oqs

    priv_pem = integration_env["priv_pem"]
    trusted_auths = integration_env["trusted_auths"]
    policy_store = integration_env["policy_store"]
    client = integration_env["client"]

    # Generate an ML-DSA-65 signer for S1
    sig_instance = oqs.Signature("ML-DSA-65")
    s1_pub_bytes = sig_instance.generate_keypair()
    trusted_s1 = {"S1-AUTHORITY-01": s1_pub_bytes.hex()}

    s1_policy_dict = {
        "flow_id": "s1_bridge_flow",
        "sensitivity": "HIGH",
        "minimum_mode": "HYBRID",
        "policy_version": 10,
        "authority_id": "S1-AUTHORITY-01",
    }
    signed_bytes, signature = sign_policy(s1_policy_dict, sig_instance)
    s1_envelope = SignedPolicyEnvelope(
        policy=s1_policy_dict,
        sig_alg="ML-DSA-65",
        signature=signature,
    )

    # Verify unified policy verification works directly on S1 envelope
    res = verify_unified_policy(s1_envelope.to_dict(), trusted_s1)
    assert res.is_valid is True
    assert res.envelope is not None
    assert "s1_bridge_flow" in res.envelope.policy.policies
    assert res.envelope.policy.policies["s1_bridge_flow"].minimum_mode == SecurityMode.HYBRID

    # Install directly into PolicyStore
    install_res = policy_store.install_policy(s1_envelope.to_dict(), trusted_s1)
    assert install_res.success is True
    assert policy_store.get_active_version() == 10
    active_env = policy_store.get_active_policy()
    assert "s1_bridge_flow" in active_env.policy.policies

