"""
Unit Tests for Gateway-to-Cloud Pipeline, Storage, and Outage Handling
"""
import os
import pytest
from qeris.s2.cloud_client import CloudForwardStatus, CloudForwardingClient
from qeris.s2.cloud_service import CloudDatabase, TelemetryIngestModel

def test_cloud_database_storage_and_segregation(temp_dir):
    db_path = os.path.join(temp_dir, "test_cloud.db")
    cloud_db = CloudDatabase(db_path=db_path)

    # Ingest record 1: Flow A, CRITICAL
    t1 = TelemetryIngestModel(
        event_id="evt_01",
        device_id="dev_01",
        flow_id="emergency_stop",
        timestamp=1000.0,
        sensitivity="CRITICAL",
        security_profile="PQC_MLKEM512_AESGCM",
        policy_version=1,
        policy_digest="a" * 64,
        payload={"alert": "ESTOP_TRIGGERED"},
    )
    # Ingest record 2: Flow B, LOW
    t2 = TelemetryIngestModel(
        event_id="evt_02",
        device_id="dev_02",
        flow_id="temperature_01",
        timestamp=1001.0,
        sensitivity="LOW",
        security_profile="CLASSICAL_ECDH_AESGCM",
        policy_version=1,
        policy_digest="a" * 64,
        payload={"temp": 21.5},
    )

    assert cloud_db.store_telemetry(t1) is True
    assert cloud_db.store_telemetry(t2) is True

    # Retrieve single event
    r1 = cloud_db.get_by_event_id("evt_01")
    assert r1 is not None
    assert r1["payload"] == {"alert": "ESTOP_TRIGGERED"}
    assert r1["sensitivity"] == "CRITICAL"

    # Verify flow segregation: Query for emergency_stop
    estop_records = cloud_db.get_telemetry(flow_id="emergency_stop")
    assert len(estop_records) == 1
    assert estop_records[0]["event_id"] == "evt_01"

    # Verify sensitivity segregation: Query for LOW
    low_records = cloud_db.get_telemetry(sensitivity="LOW")
    assert len(low_records) == 1
    assert low_records[0]["event_id"] == "evt_02"

    # Verify stats aggregation
    stats = cloud_db.get_stats()
    assert stats["total_records"] == 2
    assert len(stats["breakdown"]) == 2

def test_cloud_client_forwarding_online():
    # Mock online cloud handler
    received = []
    def mock_handler(msg):
        received.append(msg)
        return {"status": "STORED", "event_id": msg["event_id"]}

    client = CloudForwardingClient(mock_cloud_handler=mock_handler)
    res = client.forward_telemetry({"event_id": "e1", "flow_id": "f1"})

    assert res.delivered is True
    assert res.status == CloudForwardStatus.FORWARDED_TO_CLOUD
    assert len(received) == 1

def test_cloud_outage_buffering_and_flush():
    cloud_online = False
    received = []

    def conditional_cloud_handler(msg):
        if not cloud_online:
            raise ConnectionError("Cloud is down")
        received.append(msg)
        return {"status": "STORED", "event_id": msg["event_id"]}

    # Create client with max queue size = 3
    client = CloudForwardingClient(max_queue_size=3, mock_cloud_handler=conditional_cloud_handler)

    # 1. Forward during outage -> Queued
    res1 = client.forward_telemetry({"event_id": "msg_1"})
    res2 = client.forward_telemetry({"event_id": "msg_2"})
    assert res1.status == CloudForwardStatus.QUEUED_FOR_CLOUD
    assert res2.status == CloudForwardStatus.QUEUED_FOR_CLOUD
    assert client.queue_size == 2
    assert res1.delivered is False

    # 3rd message fills the queue
    res3 = client.forward_telemetry({"event_id": "msg_3"})
    assert res3.status == CloudForwardStatus.QUEUED_FOR_CLOUD
    assert client.queue_size == 3

    # 4th message exceeds max_queue_size -> Dropped!
    res4 = client.forward_telemetry({"event_id": "msg_4"})
    assert res4.status == CloudForwardStatus.CLOUD_DROPPED_QUEUE_FULL
    assert res4.delivered is False
    assert client.dropped_count == 1
    assert client.queue_size == 3

    # 2. Cloud recovers!
    cloud_online = True
    flushed = client.flush_queue()
    assert flushed == 3
    assert client.queue_size == 0
    assert len(received) == 3
    assert [m["event_id"] for m in received] == ["msg_1", "msg_2", "msg_3"]


def test_cloud_reset_admin_security(monkeypatch, temp_dir):
    """
    Verifies that /api/v1/cloud/reset enforces fail-secure admin authentication:
    1. Unconfigured admin key -> HTTP 403 Forbidden
    2. Configured admin key + missing/invalid header -> HTTP 401 Unauthorized
    3. Configured admin key + valid X-Admin-Key -> HTTP 200 OK
    """
    from fastapi.testclient import TestClient
    from qeris.s2.cloud_service import cloud_app, set_cloud_db, CloudDatabase

    test_db = CloudDatabase(db_path=os.path.join(temp_dir, "reset_test.db"))
    set_cloud_db(test_db)
    client = TestClient(cloud_app)

    # Ingest a record to verify wipe
    test_db.store_telemetry(
        TelemetryIngestModel(
            event_id="evt_reset_01",
            device_id="dev_01",
            flow_id="temp_01",
            timestamp=100.0,
            sensitivity="LOW",
            security_profile="CLASSICAL_ECDH_AESGCM",
            policy_version=1,
            policy_digest="d" * 64,
            payload="test",
        )
    )
    assert test_db.get_stats()["total_records"] == 1

    # Case 1: Unconfigured key -> 403 Forbidden
    monkeypatch.delenv("QERIS_ADMIN_API_KEY", raising=False)
    res_unset = client.post("/api/v1/cloud/reset")
    assert res_unset.status_code == 403
    assert "no admin API key is configured" in res_unset.json()["detail"]
    assert test_db.get_stats()["total_records"] == 1

    # Case 2: Configured key, but invalid or missing credential -> 401 Unauthorized
    monkeypatch.setenv("QERIS_ADMIN_API_KEY", "super-secret-admin-key-456")
    res_no_hdr = client.post("/api/v1/cloud/reset")
    assert res_no_hdr.status_code == 401
    assert "Invalid or missing admin API key" in res_no_hdr.json()["detail"]

    res_wrong_hdr = client.post(
        "/api/v1/cloud/reset",
        headers={"X-Admin-Key": "wrong-key"}
    )
    assert res_wrong_hdr.status_code == 401
    assert test_db.get_stats()["total_records"] == 1

    # Case 3: Configured key + valid credential -> 200 OK
    res_valid = client.post(
        "/api/v1/cloud/reset",
        headers={"X-Admin-Key": "super-secret-admin-key-456"}
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["status"] == "RESET_COMPLETED"
    assert test_db.get_stats()["total_records"] == 0

