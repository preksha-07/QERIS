"""
Unit Tests for Security Floor and Sensitivity Enforcement
"""
import pytest
from fastapi.testclient import TestClient
from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore

@pytest.fixture
def test_gateway(temp_dir, authority_keys):
    policy_db = f"{temp_dir}/policy.db"
    reg_db = f"{temp_dir}/registry.db"
    store = PolicyStore(policy_db)
    registry = DeviceRegistry(reg_db)

    # Register devices
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_pqc_only",
            supported_modes=["PQC"],
            supported_security_profiles=["PQC_MLKEM512_AESGCM"],
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_classical_only",
            supported_modes=["CLASSICAL"],
            supported_security_profiles=["CLASSICAL_ECDH_AESGCM"],
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_hybrid",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                "CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"
            ],
        )
    )

    # Install signed policy
    auth_id = authority_keys["authority_id"]
    doc = PolicyDocumentModel(
        authority_id=auth_id,
        policy_version=1,
        policies={
            "crit_flow": FlowPolicyModel(
                flow_id="crit_flow",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
            "low_flow": FlowPolicyModel(
                flow_id="low_flow",
                device_scope=["*"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=["CLASSICAL_ECDH_AESGCM", "PQC_MLKEM512_AESGCM"],
            ),
        },
    )
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {auth_id: authority_keys["pub_pem"]}
    store.install_policy(envelope, trusted)

    app = create_gateway_app(
        policy_store=store,
        registry=registry,
        trusted_authorities=trusted,
    )
    return TestClient(app)

def test_critical_flow_allows_pqc(test_gateway):
    resp = test_gateway.post(
        "/check-flow",
        json={
            "device_id": "dev_hybrid",
            "flow_id": "crit_flow",
            "requested_mode": "PQC",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["sensitivity"] == "CRITICAL"
    assert data["minimum_mode"] == "PQC"

def test_critical_flow_blocks_classical_downgrade(test_gateway):
    resp = test_gateway.post(
        "/check-flow",
        json={
            "device_id": "dev_hybrid",
            "flow_id": "crit_flow",
            "requested_mode": "CLASSICAL",
        },
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["decision"] in ("REJECT", "FLOOR_UNREACHABLE")
    assert "below signed security floor" in data["reason"]

def test_device_supplied_sensitivity_cannot_override_policy(test_gateway):
    # Device claims sensitivity is "LOW" to trick gateway into allowing CLASSICAL on crit_flow
    resp = test_gateway.post(
        "/check-flow",
        json={
            "device_id": "dev_hybrid",
            "flow_id": "crit_flow",
            "requested_mode": "CLASSICAL",
            "device_reported_sensitivity": "LOW",
        },
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["decision"] in ("REJECT", "FLOOR_UNREACHABLE")
    # Verified policy sensitivity must remain CRITICAL!
    assert data.get("sensitivity") == "CRITICAL"

def test_capability_mismatch_floor_unreachable(test_gateway):
    # dev_classical_only requests crit_flow
    resp = test_gateway.post(
        "/check-flow",
        json={
            "device_id": "dev_classical_only",
            "flow_id": "crit_flow",
            "requested_mode": "CLASSICAL",
        },
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["decision"] in ("REJECT", "FLOOR_UNREACHABLE")

def test_unknown_flow_rejected(test_gateway):
    resp = test_gateway.post(
        "/check-flow",
        json={
            "device_id": "dev_hybrid",
            "flow_id": "nonexistent_flow",
            "requested_mode": "CLASSICAL",
        },
    )
    assert resp.status_code == 404
    assert resp.json()["decision"] == "REJECT"
