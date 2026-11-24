"""
QERIS S2: Unit & Integration Tests for Comparative Baselines B1–B7

Verifies gateway behavior across the full spectrum of research baselines:
- B1: Static Classical
- B2: Static Hybrid
- B3: Static PQC
- B4: Sensitivity-Only (no cause-aware recovery)
- B5: Downgrade-on-Failure (naive industry fallback that permits floor violations)
- B6: Static Retry with Floor (blind retries)
- B7: Full Gateway (QERIS cause-classified, security-floor-bounded recovery)
"""
import pytest
from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import BaselineMode, GatewayConfig, SecurityProfile
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore


@pytest.fixture
def baseline_test_env(temp_dir, authority_keys):
    db_path = f"{temp_dir}/policy_baselines.db"
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Install standard 3-tier policy
    doc = PolicyDocumentModel(
        authority_id=authority_keys["authority_id"],
        policy_version=1,
        policies={
            "flow_low": FlowPolicyModel(
                flow_id="flow_low",
                device_scope=["*"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=[
                    "CLASSICAL_ECDH_AESGCM",
                    "HYBRID_X25519_MLKEM_AESGCM",
                    "PQC_MLKEM512_AESGCM",
                ],
            ),
            "flow_medium": FlowPolicyModel(
                flow_id="flow_medium",
                device_scope=["*"],
                sensitivity="MEDIUM",
                minimum_mode="HYBRID",
                approved_security_profiles=[
                    "HYBRID_X25519_MLKEM_AESGCM",
                    "PQC_MLKEM512_AESGCM",
                ],
            ),
            "flow_critical": FlowPolicyModel(
                flow_id="flow_critical",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
        },
    )
    env = sign_policy_document(doc, authority_keys["priv_pem"])
    store.install_policy(env, trusted)

    # Register capability profile supporting all modes
    registry = DeviceRegistry(db_path=f"{temp_dir}/registry_baselines.db")
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="test_device",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                "CLASSICAL_ECDH_AESGCM",
                "HYBRID_X25519_MLKEM_AESGCM",
                "PQC_MLKEM512_AESGCM",
            ],
            ram_bytes_available=256 * 1024,
            max_packet_size_mtu=1500,
        )
    )

    config = GatewayConfig(
        baseline_mode=BaselineMode.FULL_GATEWAY,
        admin_api_key="test-baseline-admin-key",
    )
    app = create_gateway_app(
        policy_store=store,
        registry=registry,
        trusted_authorities=trusted,
        config=config,
    )
    return TestClient(app, headers={"X-Admin-Key": "test-baseline-admin-key"})


def test_b1_static_classical(baseline_test_env):
    """B1: Static Classical allows Classical on Low flows, but rejects higher flows and non-classical requests."""
    client = baseline_test_env
    # Switch to STATIC_CLASSICAL
    resp = client.post("/api/v1/admin/baseline", json={"baseline_mode": "static_classical"})
    assert resp.status_code == 200
    assert resp.json()["baseline_mode"] == "static_classical"

    # Low flow on Classical -> ALLOW
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_low", "requested_mode": "CLASSICAL"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Critical flow on Classical -> REJECT (Static Classical cannot meet PQC floor)
    r2 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "CLASSICAL"})
    assert r2.status_code == 403
    assert r2.json()["decision"] == "REJECT"

    # Requesting PQC in Static Classical mode -> REJECT (Static Classical only permits Classical)
    r3 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_low", "requested_mode": "PQC"})
    assert r3.status_code == 403
    assert r3.json()["decision"] == "REJECT"


def test_b2_static_hybrid(baseline_test_env):
    """B2: Static Hybrid allows Hybrid on Medium flows, but rejects Critical flows needing PQC."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "static_hybrid"})

    # Medium flow on Hybrid -> ALLOW
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_medium", "requested_mode": "HYBRID"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Critical flow on Hybrid -> REJECT (cannot meet PQC floor)
    r2 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "HYBRID"})
    assert r2.status_code == 403
    assert r2.json()["decision"] == "REJECT"


def test_b3_static_pqc(baseline_test_env):
    """B3: Static PQC allows PQC on Critical flows, but rejects non-PQC requests."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "static_pqc"})

    # Critical flow on PQC -> ALLOW
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "PQC"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Low flow requesting Classical in Static PQC mode -> REJECT
    r2 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_low", "requested_mode": "CLASSICAL"})
    assert r2.status_code == 403
    assert r2.json()["decision"] == "REJECT"


def test_b4_sensitivity_only(baseline_test_env):
    """B4: Sensitivity-Only enforces floor based strictly on tier without adaptive recovery."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "sensitivity_only"})

    # Classical on Low -> ALLOW
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_low", "requested_mode": "CLASSICAL"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Classical downgrade on Critical -> REJECT
    r2 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "CLASSICAL"})
    assert r2.status_code == 403
    assert r2.json()["decision"] == "REJECT"


def test_b5_downgrade_on_failure(baseline_test_env):
    """B5: Downgrade-on-Failure permits downgrade below floor (for comparative research evaluation)."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "downgrade_on_failure"})

    # Critical flow requesting Classical -> ALLOWED in B5 (simulates naive industry fallback)
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "CLASSICAL"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"


def test_b6_static_retry_with_floor(baseline_test_env):
    """B6: Static Retry enforces floor strictly."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "static_retry_with_floor"})

    # Critical flow on Classical -> REJECT
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "CLASSICAL"})
    assert r1.status_code == 403
    assert r1.json()["decision"] == "REJECT"


def test_b7_full_gateway(baseline_test_env):
    """B7: Full Gateway (QERIS default) cause-classified, floor-bounded recovery."""
    client = baseline_test_env
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "full_gateway"})

    # Critical flow on PQC -> ALLOW
    r1 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "PQC"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Critical flow on Classical -> REJECT (downgrade blocked)
    r2 = client.post("/check-flow", json={"device_id": "test_device", "flow_id": "flow_critical", "requested_mode": "CLASSICAL"})
    assert r2.status_code == 403
    assert r2.json()["decision"] == "REJECT"
