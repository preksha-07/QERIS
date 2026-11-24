"""
Integration and End-to-End Tests: Device -> Gateway -> Cloud Pipeline
"""
import os
import pytest
from fastapi.testclient import TestClient
from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.cloud_client import CloudForwardingClient
from qeris.s2.cloud_service import CloudDatabase, cloud_app
from qeris.s2.data_replay import DatasetReplayer
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore

@pytest.fixture
def integrated_pipeline(temp_dir, authority_keys):
    policy_db = f"{temp_dir}/policy.db"
    reg_db = f"{temp_dir}/reg.db"
    cloud_db_path = f"{temp_dir}/cloud.db"

    store = PolicyStore(policy_db)
    registry = DeviceRegistry(reg_db)
    cloud_db = CloudDatabase(cloud_db_path)

    # In-process cloud client routing to local cloud database
    def in_process_cloud_handler(msg):
        from qeris.s2.cloud_service import TelemetryIngestModel
        item = TelemetryIngestModel.model_validate(msg)
        ok = cloud_db.store_telemetry(item)
        return {"status": "STORED" if ok else "FAILED"}

    cloud_client = CloudForwardingClient(mock_cloud_handler=in_process_cloud_handler)

    # Register devices
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_001",
            supported_modes=["CLASSICAL", "HYBRID"],
            supported_security_profiles=["CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM"],
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_002",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                "CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"
            ],
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="dev_esp32_constrained_01",
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
            "temperature_01": FlowPolicyModel(
                flow_id="temperature_01",
                device_scope=["*"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=["CLASSICAL_ECDH_AESGCM", "PQC_MLKEM512_AESGCM"],
            ),
            "emergency_stop": FlowPolicyModel(
                flow_id="emergency_stop",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
            "flow_critical_01": FlowPolicyModel(
                flow_id="flow_critical_01",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
        },
    )
    envelope = sign_policy_document(doc, authority_keys["priv_pem"])
    trusted = {auth_id: authority_keys["pub_pem"]}
    store.install_policy(envelope, trusted)

    gateway_app = create_gateway_app(
        policy_store=store,
        registry=registry,
        cloud_client=cloud_client,
        trusted_authorities=trusted,
    )
    return {
        "gateway_client": TestClient(gateway_app),
        "cloud_db": cloud_db,
    }

def test_accepted_telemetry_reaches_cloud(integrated_pipeline):
    gw = integrated_pipeline["gateway_client"]
    cloud_db = integrated_pipeline["cloud_db"]

    # 1. Flow check for LOW flow -> ALLOW
    res_check = gw.post(
        "/check-flow",
        json={"device_id": "dev_001", "flow_id": "temperature_01", "requested_mode": "CLASSICAL"},
    )
    assert res_check.status_code == 200
    assert res_check.json()["decision"] == "ALLOW"

    # 2. Submit telemetry
    res_tel = gw.post(
        "/api/v1/telemetry",
        json={
            "device_id": "dev_001",
            "flow_id": "temperature_01",
            "payload": {"temp_c": 24.2, "status": "ok"},
        },
    )
    assert res_tel.status_code == 200
    event_id = res_tel.json()["event_id"]

    # 3. Retrieve directly from Cloud Database
    stored = cloud_db.get_by_event_id(event_id)
    assert stored is not None
    assert stored["device_id"] == "dev_001"
    assert stored["flow_id"] == "temperature_01"
    assert stored["sensitivity"] == "LOW"
    assert stored["payload"] == {"temp_c": 24.2, "status": "ok"}

def test_rejected_flow_does_not_reach_cloud(integrated_pipeline):
    gw = integrated_pipeline["gateway_client"]
    cloud_db = integrated_pipeline["cloud_db"]

    # Attempt to request CRITICAL flow over CLASSICAL -> REJECTED
    res_check = gw.post(
        "/check-flow",
        json={"device_id": "dev_002", "flow_id": "emergency_stop", "requested_mode": "CLASSICAL"},
    )
    assert res_check.status_code == 403
    assert res_check.json()["decision"] in ("REJECT", "FLOOR_UNREACHABLE")

    # Cloud DB must have ZERO records for emergency_stop
    records = cloud_db.get_telemetry(flow_id="emergency_stop")
    assert len(records) == 0

def test_data_replay_integration(integrated_pipeline):
    gw = integrated_pipeline["gateway_client"]
    cloud_db = integrated_pipeline["cloud_db"]

    replayer = DatasetReplayer()
    runs = replayer.find_available_runs()
    assert len(runs) > 0
    assert "pilot_smoke" in runs

    # Replay 20 events from real pilot_smoke dataset through gateway
    stats = replayer.replay_through_gateway(gw, run_id="pilot_smoke", max_events=20)

    assert stats["total_replayed"] == 20
    assert stats["total_replayed"] == stats["allowed_count"] + stats["rejected_count"]
    assert len(stats["flows_exercised"]) > 0
    assert len(stats["devices_exercised"]) > 0

    # In pilot_smoke, flow_critical_01 requested with CLASSICAL mode was rejected,
    # protecting the security floor across all replayed events!
    assert stats["rejected_count"] > 0
