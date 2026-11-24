"""
QERIS S2: Phase 2 Baseline Freeze & Experimental Readiness Tests

Comprehensive verification of:
1. Centralized configuration model (GatewayConfig) and deterministic RFC 8785 digest.
2. Baseline freeze validation (rejects invalid baseline strings with HTTP 422).
3. Baseline discovery and metadata endpoints (GET/POST /api/v1/admin/baseline).
4. State reset and run isolation (POST /api/v1/admin/reset).
5. Exact baseline-specific recovery properties (B1-B7).
6. Run ID and scenario context propagation to responses and audit logs.
"""
import json
import pytest
from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import (
    BASELINE_DESCRIPTIONS,
    BASELINE_RECOVERY_PROPERTIES,
    BaselineMode,
    GatewayConfig,
    SecurityProfile,
)
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore
from qeris.s2.audit_logger import GatewayAuditLogger


@pytest.fixture
def freeze_test_env(temp_dir, authority_keys):
    db_path = f"{temp_dir}/policy_freeze.db"
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
                    SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
            "flow_medium": FlowPolicyModel(
                flow_id="flow_medium",
                device_scope=["*"],
                sensitivity="MEDIUM",
                minimum_mode="HYBRID",
                approved_security_profiles=[
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
            "flow_critical": FlowPolicyModel(
                flow_id="flow_critical",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=[
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                    SecurityProfile.PQC_MLKEM768_AESGCM.value,
                ],
            ),
        },
    )
    env = sign_policy_document(doc, authority_keys["priv_pem"])
    store.install_policy(env, trusted)

    # Register standard device and constrained device with small MTU
    registry = DeviceRegistry(db_path=f"{temp_dir}/registry_freeze.db")
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_standard",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                SecurityProfile.PQC_MLKEM512_AESGCM.value,
                SecurityProfile.PQC_MLKEM768_AESGCM.value,
            ],
            ram_bytes_available=512 * 1024,
            max_packet_size_mtu=1500,
        )
    )
    # Constrained MTU device (MTU 1280 < PQC wire size 1820)
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_small_mtu",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                SecurityProfile.PQC_MLKEM512_AESGCM.value,
            ],
            ram_bytes_available=256 * 1024,
            max_packet_size_mtu=1280,
        )
    )

    audit_path = f"{temp_dir}/audit_freeze.jsonl"
    audit_logger = GatewayAuditLogger(log_path=audit_path)

    config = GatewayConfig(
        baseline_mode=BaselineMode.FULL_GATEWAY,
        admin_api_key="test-freeze-admin-key",
        audit_log_path=audit_path,
        policy_db_path=db_path,
        registry_db_path=f"{temp_dir}/registry_freeze.db",
    )

    app = create_gateway_app(
        policy_store=store,
        registry=registry,
        audit_logger=audit_logger,
        trusted_authorities=trusted,
        config=config,
    )
    return TestClient(app, headers={"X-Admin-Key": config.admin_api_key}), audit_path, config


def test_gateway_config_model_and_digest():
    """Verify GatewayConfig initialization, to_dict(), and canonical SHA-256 digest reproducibility."""
    cfg1 = GatewayConfig(baseline_mode=BaselineMode.FULL_GATEWAY)
    cfg2 = GatewayConfig(baseline_mode=BaselineMode.FULL_GATEWAY)
    assert cfg1.compute_digest() == cfg2.compute_digest()
    assert len(cfg1.compute_digest()) == 64

    # Changing a parameter must alter the digest
    cfg3 = GatewayConfig(baseline_mode=BaselineMode.DOWNGRADE_ON_FAILURE)
    assert cfg3.compute_digest() != cfg1.compute_digest()


def test_admin_config_endpoints(freeze_test_env):
    """Verify GET and POST /api/v1/admin/config endpoints."""
    client, _, _ = freeze_test_env

    # 1. GET config
    res = client.get("/api/v1/admin/config")
    assert res.status_code == 200
    data = res.json()
    assert data["frozen"] is True
    assert data["config_version"] == "2.0.0-frozen"
    assert "config_digest" in data
    assert data["config"]["baseline_mode"] == "full_gateway"

    # 2. POST update config
    res_up = client.post(
        "/api/v1/admin/config",
        json={"rate_limit_capacity": 25.0, "rate_limit_enabled": False},
    )
    assert res_up.status_code == 200
    up_data = res_up.json()
    assert up_data["config"]["rate_limit_capacity"] == 25.0
    assert up_data["config"]["rate_limit_enabled"] is False
    assert up_data["config_digest"] != data["config_digest"]


def test_baseline_discovery_and_strict_validation(freeze_test_env):
    """Verify GET /api/v1/admin/baseline and strict rejection of invalid baseline values."""
    client, _, _ = freeze_test_env

    # GET active baseline metadata
    res = client.get("/api/v1/admin/baseline")
    assert res.status_code == 200
    b_data = res.json()
    assert b_data["baseline_mode"] == "full_gateway"
    assert b_data["frozen"] is True
    assert len(b_data["all_available_baselines"]) == 7

    # Reject invalid baseline string with HTTP 422
    res_invalid = client.post("/api/v1/admin/baseline", json={"baseline_mode": "bogus_mode_invalid"})
    assert res_invalid.status_code == 422

    # Accept valid baseline
    res_valid = client.post("/api/v1/admin/baseline", json={"baseline_mode": "static_classical"})
    assert res_valid.status_code == 200
    assert res_valid.json()["baseline_mode"] == "static_classical"


def test_state_reset_and_isolation(freeze_test_env):
    """Verify POST /api/v1/admin/reset clears state and isolates experiment runs."""
    client, _, _ = freeze_test_env

    # 1. Switch to B5 (downgrade_on_failure) and verify floor violation is permitted
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "downgrade_on_failure"})
    r_b5 = client.post(
        "/check-flow",
        json={
            "device_id": "dev_standard",
            "flow_id": "flow_critical",
            "requested_mode": "CLASSICAL",
        },
    )
    assert r_b5.status_code == 200
    assert r_b5.json()["floor_violation"] is True

    # 2. Perform state reset back to default B7 (full_gateway)
    res_reset = client.post(
        "/api/v1/admin/reset",
        json={
            "reset_rate_limits": True,
            "clear_sessions": True,
            "reset_baseline": "full_gateway",
            "run_id": "exp_reset_run_01",
        },
    )
    assert res_reset.status_code == 200
    reset_data = res_reset.json()
    assert reset_data["status"] == "RESET_COMPLETED"
    assert reset_data["baseline_mode"] == "full_gateway"

    # 3. Verify B7 strictly enforces floor immediately after reset
    r_b7 = client.post(
        "/check-flow",
        json={
            "device_id": "dev_standard",
            "flow_id": "flow_critical",
            "requested_mode": "CLASSICAL",
        },
    )
    assert r_b7.status_code == 403
    assert r_b7.json()["decision"] == "REJECT"
    assert r_b7.json()["floor_violation"] is False


def test_b4_vs_b7_adaptive_recovery_distinction(freeze_test_env):
    """Verify that B4 suppresses adaptive fragmentation hints, whereas B7 provides them."""
    client, _, _ = freeze_test_env

    # Test B4 (Sensitivity-Only): floor satisfied, but NO adaptive recovery hints
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "sensitivity_only"})
    r_b4 = client.post(
        "/check-flow",
        json={
            "device_id": "dev_small_mtu",
            "flow_id": "flow_critical",
            "requested_mode": "PQC",
        },
    )
    assert r_b4.status_code == 200
    assert r_b4.json()["adaptive_recovery"] is False
    assert r_b4.json()["readiness"]["requires_fragmentation"] is False

    # Test B7 (Full Gateway): floor satisfied, AND adaptive fragmentation hint provided
    client.post("/api/v1/admin/baseline", json={"baseline_mode": "full_gateway"})
    r_b7 = client.post(
        "/check-flow",
        json={
            "device_id": "dev_small_mtu",
            "flow_id": "flow_critical",
            "requested_mode": "PQC",
        },
    )
    assert r_b7.status_code == 200
    assert r_b7.json()["adaptive_recovery"] is True
    assert r_b7.json()["readiness"]["requires_fragmentation"] is True


def test_run_id_and_scenario_context_propagation(freeze_test_env):
    """Verify that run_id and scenario are returned in response and written to audit log."""
    client, audit_path, _ = freeze_test_env

    run_id = "bench_run_alpha_42"
    scenario = "loss_timeout_scenario_03"

    res = client.post(
        "/check-flow",
        json={
            "device_id": "dev_standard",
            "flow_id": "flow_low",
            "requested_mode": "CLASSICAL",
            "run_id": run_id,
            "scenario": scenario,
        },
    )
    assert res.status_code == 200
    resp_data = res.json()
    assert resp_data["run_id"] == run_id
    assert resp_data["scenario"] == scenario
    assert resp_data["baseline_mode"] == "full_gateway"

    # Verify audit log recorded run_id, scenario, and baseline_mode
    with open(audit_path, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    matching = [
        l for l in lines
        if l.get("run_id") == run_id and l.get("scenario") == scenario
    ]
    assert len(matching) >= 1
    assert matching[-1]["baseline_mode"] == "full_gateway"
    assert matching[-1]["decision"] == "ALLOW"
