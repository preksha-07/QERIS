"""
QERIS S2: Integration & Deployment Resilience Tests

Tests:
1. Container & Deployment health probe consistency (/health, /api/v1/gateway/health, /api/v1/cloud/health).
2. Standard ASGI application entrypoint alias verification (cloud_service:app).
3. Live Gateway-to-Cloud forwarding, buffering, and database storage.
4. Comprehensive state reset (rate limits, sessions, and cloud outage queue).
5. Failure handling and resilience when cloud service is unreachable.
6. Administrative API key authentication middleware.
7. Malformed request and strict schema validation.
"""
import json
import pytest
from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.cloud_client import CloudForwardingClient, CloudForwardStatus
from qeris.s2.cloud_service import CloudDatabase, cloud_app, app as cloud_asgi_app
from qeris.s2.config import BaselineMode, GatewayConfig, SecurityProfile
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore
from qeris.s2.audit_logger import GatewayAuditLogger


@pytest.fixture
def integration_env(temp_dir, authority_keys):
    policy_db = f"{temp_dir}/integration_policy.db"
    reg_db = f"{temp_dir}/integration_registry.db"
    cloud_db_path = f"{temp_dir}/integration_cloud.db"
    audit_log = f"{temp_dir}/integration_audit.jsonl"

    store = PolicyStore(db_path=policy_db)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    doc = PolicyDocumentModel(
        authority_id=authority_keys["authority_id"],
        policy_version=1,
        policies={
            "telemetry_flow": FlowPolicyModel(
                flow_id="telemetry_flow",
                device_scope=["*"],
                sensitivity="MEDIUM",
                minimum_mode="HYBRID",
                approved_security_profiles=[
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
        },
    )
    env = sign_policy_document(doc, authority_keys["priv_pem"])
    store.install_policy(env, trusted)

    registry = DeviceRegistry(db_path=reg_db)
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="sensor_node_01",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                SecurityProfile.PQC_MLKEM512_AESGCM.value,
            ],
            ram_bytes_available=512 * 1024,
            max_packet_size_mtu=1500,
        )
    )

    cloud_db = CloudDatabase(db_path=cloud_db_path)
    from qeris.s2.cloud_service import set_cloud_db
    set_cloud_db(cloud_db)
    cloud_test_client = TestClient(cloud_app)

    # In-process bridge to cloud API
    def live_cloud_bridge(payload):
        resp = cloud_test_client.post("/api/v1/cloud/ingest", json=payload)
        return {"status": "STORED" if resp.status_code == 201 else "FAILED", "detail": resp.text}

    cloud_client = CloudForwardingClient(mock_cloud_handler=live_cloud_bridge)
    audit_logger = GatewayAuditLogger(log_path=audit_log)

    config = GatewayConfig(
        baseline_mode=BaselineMode.FULL_GATEWAY,
        admin_api_key="test-integration-admin-key",
        audit_log_path=audit_log,
        policy_db_path=policy_db,
        registry_db_path=reg_db,
        cloud_db_path=cloud_db_path,
    )

    gw_app = create_gateway_app(
        policy_store=store,
        registry=registry,
        cloud_client=cloud_client,
        audit_logger=audit_logger,
        trusted_authorities=trusted,
        config=config,
    )

    gw_client = TestClient(gw_app, headers={"X-Admin-Key": config.admin_api_key})
    return gw_client, cloud_test_client, cloud_client, cloud_db, audit_log


def test_health_check_endpoints_and_asgi_alias(integration_env):
    """Verify health probes and standard ASGI application entrypoints for Docker."""
    gw_client, cloud_client, _, _, _ = integration_env

    # 1. Gateway health probes
    r1 = gw_client.get("/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "UP"

    r2 = gw_client.get("/api/v1/gateway/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "UP"

    r3 = gw_client.get("/api/v1/gateway/status")
    assert r3.status_code == 200
    assert r3.json()["status"] == "ONLINE"

    # 2. Cloud health probe
    r_cloud = cloud_client.get("/api/v1/cloud/health")
    assert r_cloud.status_code == 200
    assert r_cloud.json()["status"] == "UP"

    # 3. Verify cloud_service `app` alias
    assert cloud_asgi_app is cloud_app


def test_gateway_to_cloud_forwarding_and_storage(integration_env):
    """Verify live telemetry flow from gateway to cloud ingestion and database persistence."""
    gw_client, cloud_client, _, cloud_db, _ = integration_env

    payload = {"temperature_celsius": 24.8, "humidity_percent": 55.2}
    resp = gw_client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "sensor_node_01",
            "flow_id": "telemetry_flow",
            "payload": payload,
            "run_id": "integration_test_run",
        },
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "ACCEPTED"
    assert res_data["cloud_delivery"] == "FORWARDED_TO_CLOUD"

    # Verify cloud database received the telemetry
    records = cloud_db.get_telemetry(flow_id="telemetry_flow")
    assert len(records) >= 1
    assert records[0]["payload"] == payload
    assert records[0]["sensitivity"] == "MEDIUM"

    # Verify stats
    stats = cloud_client.get("/api/v1/cloud/stats").json()
    assert stats["total_records"] >= 1


def test_cloud_failure_buffering_and_resilience(integration_env):
    """Verify gateway does NOT crash when cloud is offline; buffers in outage queue."""
    gw_client, _, client_obj, _, _ = integration_env

    # Simulate cloud failure by injecting failing mock handler
    client_obj._mock_cloud_handler = lambda msg: {"status": "FAILED", "detail": "Connection refused"}

    resp = gw_client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "sensor_node_01",
            "flow_id": "telemetry_flow",
            "payload": {"reading": "offline_metric_01"},
        },
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "ACCEPTED"
    assert res_data["cloud_delivery"] == "QUEUED_FOR_CLOUD"
    assert client_obj.queue_size >= 1


def test_comprehensive_state_reset(integration_env):
    """Verify POST /api/v1/admin/reset clears rate limits, sessions, and cloud outage queue."""
    gw_client, _, client_obj, _, _ = integration_env

    # 1. Fill outage queue and switch baseline
    client_obj._mock_cloud_handler = lambda msg: {"status": "FAILED", "detail": "Outage"}
    gw_client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "sensor_node_01",
            "flow_id": "telemetry_flow",
            "payload": {"reading": "buffered_data"},
        },
    )
    assert client_obj.queue_size > 0

    gw_client.post("/api/v1/admin/baseline", json={"baseline_mode": "downgrade_on_failure"})

    # 2. Trigger comprehensive reset
    reset_resp = gw_client.post(
        "/api/v1/admin/reset",
        json={
            "reset_rate_limits": True,
            "clear_sessions": True,
            "reset_cloud_queue": True,
            "reset_baseline": "full_gateway",
            "run_id": "reset_test_01",
        },
    )
    assert reset_resp.status_code == 200
    r_data = reset_resp.json()
    assert r_data["status"] == "RESET_COMPLETED"
    assert r_data["baseline_mode"] == "full_gateway"
    assert r_data["cloud_queue_cleared"] is True

    # Verify queue is empty
    assert client_obj.queue_size == 0
    assert client_obj.dropped_count == 0


def test_admin_api_key_protection(temp_dir, authority_keys):
    """Verify that when admin_api_key is configured, admin endpoints enforce authentication."""
    db_path = f"{temp_dir}/admin_auth.db"
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    config = GatewayConfig(
        admin_api_key="top-secret-admin-key",
        policy_db_path=db_path,
        registry_db_path=f"{temp_dir}/admin_reg.db",
        cloud_db_path=f"{temp_dir}/admin_cloud.db",
    )

    app = create_gateway_app(
        policy_store=store,
        trusted_authorities=trusted,
        config=config,
    )
    client = TestClient(app)

    # 1. Operational endpoint (/check-flow) is unauthenticated
    r_op = client.post("/check-flow", json={"device_id": "dev1", "flow_id": "flow1"})
    assert r_op.status_code in (404, 503, 403)  # Not 401 Unauthorized!

    # 2. Admin endpoint without key -> 401
    r_unauth = client.get("/api/v1/admin/baseline")
    assert r_unauth.status_code == 401

    # 3. Admin endpoint with X-Admin-Key -> 200
    r_hdr = client.get("/api/v1/admin/baseline", headers={"X-Admin-Key": "top-secret-admin-key"})
    assert r_hdr.status_code == 200
    assert r_hdr.json()["baseline_mode"] == "full_gateway"

    # 4. Admin endpoint with Bearer token -> 200
    r_bearer = client.get("/api/v1/admin/baseline", headers={"Authorization": "Bearer top-secret-admin-key"})
    assert r_bearer.status_code == 200


def test_malformed_and_invalid_request_rejection(integration_env):
    """Verify strict rejection of malformed JSON and missing fields."""
    gw_client, _, _, _, _ = integration_env

    # 1. Invalid JSON body to /check-flow -> 422
    r1 = gw_client.post("/check-flow", content=b"not a json string", headers={"Content-Type": "application/json"})
    assert r1.status_code == 422

    # 2. Missing required device_id -> 422
    r2 = gw_client.post("/check-flow", json={"flow_id": "telemetry_flow"})
    assert r2.status_code == 422

    # 3. Invalid baseline update -> 422
    r3 = gw_client.post("/api/v1/admin/baseline", json={"baseline_mode": "invalid_mode_xyz"})
    assert r3.status_code == 422


def test_admin_auth_fail_secure_when_key_unset(temp_dir, authority_keys):
    """Verify fail-secure posture: when admin_api_key is None or empty, admin access is rejected (403)."""
    db_path = f"{temp_dir}/admin_fail_secure.db"
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Case 1: admin_api_key is None
    config_none = GatewayConfig(
        admin_api_key=None,
        policy_db_path=db_path,
        registry_db_path=f"{temp_dir}/admin_fs_reg1.db",
        cloud_db_path=f"{temp_dir}/admin_fs_cloud1.db",
    )
    app1 = create_gateway_app(policy_store=store, trusted_authorities=trusted, config=config_none)
    client1 = TestClient(app1)
    r1 = client1.get("/api/v1/admin/baseline")
    assert r1.status_code == 403
    assert "Forbidden" in r1.json()["detail"]

    # Case 2: admin_api_key is empty string ""
    config_empty = GatewayConfig(
        admin_api_key="",
        policy_db_path=db_path,
        registry_db_path=f"{temp_dir}/admin_fs_reg2.db",
        cloud_db_path=f"{temp_dir}/admin_fs_cloud2.db",
    )
    app2 = create_gateway_app(policy_store=store, trusted_authorities=trusted, config=config_empty)
    client2 = TestClient(app2)
    r2 = client2.get("/api/v1/admin/baseline")
    assert r2.status_code == 403
    assert "Forbidden" in r2.json()["detail"]


def test_admin_auth_valid_and_invalid_credentials(temp_dir, authority_keys):
    """Verify admin endpoints with missing, invalid, and valid credentials."""
    db_path = f"{temp_dir}/admin_creds.db"
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}
    secret_key = "test-explicit-secret-key-99"

    config = GatewayConfig(
        admin_api_key=secret_key,
        policy_db_path=db_path,
        registry_db_path=f"{temp_dir}/admin_creds_reg.db",
        cloud_db_path=f"{temp_dir}/admin_creds_cloud.db",
    )
    app = create_gateway_app(policy_store=store, trusted_authorities=trusted, config=config)
    client = TestClient(app)

    # 1. Missing header -> 401
    assert client.get("/api/v1/admin/baseline").status_code == 401

    # 2. Invalid header -> 401
    assert client.get("/api/v1/admin/baseline", headers={"X-Admin-Key": "wrong-secret"}).status_code == 401

    # 3. Valid X-Admin-Key -> 200
    r_hdr = client.get("/api/v1/admin/baseline", headers={"X-Admin-Key": secret_key})
    assert r_hdr.status_code == 200

    # 4. Valid Authorization Bearer -> 200
    r_bearer = client.get("/api/v1/admin/baseline", headers={"Authorization": f"Bearer {secret_key}"})
    assert r_bearer.status_code == 200


def test_admin_key_redaction_in_config_and_audit(temp_dir, authority_keys):
    """Verify that admin key is never leaked in plaintext via config serialization or logs."""
    secret_key = "super-secret-admin-passphrase-to-never-leak"
    audit_log = f"{temp_dir}/audit_redact.jsonl"
    logger = GatewayAuditLogger(log_path=audit_log)

    config = GatewayConfig(admin_api_key=secret_key, audit_log_path=audit_log)
    c_dict = config.to_dict()
    assert secret_key not in json.dumps(c_dict)
    assert c_dict["admin_api_key"] == "[CONFIGURED]"

    # Log event with details containing secret
    logger.log_event("admin_test", device_id="gw", flow_id="*", decision="ALLOW", reason="test_redaction", details={"admin_api_key": secret_key})
    with open(audit_log, "r", encoding="utf-8") as f:
        log_content = f.read()
    assert secret_key not in log_content
    assert "[REDACTED]" in log_content


def test_genuine_tls_handshake_with_live_https_server(temp_dir):
    """
    Demonstrate genuine Gateway-to-Cloud TLS:
    1. Real HTTPS server with SSLContext and self-signed certificate.
    2. CloudForwardingClient performs authentic TLS handshake with certificate validation.
    3. Verify connection succeeds and delivers telemetry over TLS.
    """
    import http.server
    import ssl
    import threading
    from pathlib import Path
    from qeris.s2.certs import generate_self_signed_tls_cert

    cert_path = Path(temp_dir) / "live_cloud_cert.pem"
    key_path = Path(temp_dir) / "live_cloud_key.pem"
    generate_self_signed_tls_cert(cert_path=cert_path, key_path=key_path, common_name="localhost")

    received_payloads = []

    class MockCloudHTTPSHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            received_payloads.append(json.loads(body.decode("utf-8")))
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "STORED", "event_id": "tls_evt_101"}')

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), MockCloudHTTPSHandler)
    server_port = server.server_address[1]

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Initialize client pointing to live HTTPS server with trusted cert
        client = CloudForwardingClient(
            cloud_url=f"https://127.0.0.1:{server_port}",
            ca_cert_path=str(cert_path),
            timeout_seconds=5.0,
        )
        msg = {"event_id": "tls_evt_101", "flow_id": "crit_flow", "payload": {"temp": 21.5}}
        res = client.forward_telemetry(msg)

        assert res.delivered is True
        assert res.status == CloudForwardStatus.FORWARDED_TO_CLOUD
        assert "HTTP 201 OK" in res.detail
        assert len(received_payloads) == 1
        assert received_payloads[0]["event_id"] == "tls_evt_101"
    finally:
        server.shutdown()


def test_genuine_tls_rejection_of_untrusted_certificate(temp_dir):
    """
    Demonstrate that certificate verification is genuinely active:
    When client is configured with an untrusted CA cert, TLS handshake fails with verification error.
    """
    import http.server
    import ssl
    import threading
    from pathlib import Path
    from qeris.s2.certs import generate_self_signed_tls_cert

    server_cert = Path(temp_dir) / "server_cert.pem"
    server_key = Path(temp_dir) / "server_key.pem"
    generate_self_signed_tls_cert(cert_path=server_cert, key_path=server_key, common_name="localhost")

    # Generate a DIFFERENT untrusted cert that did not sign server's cert
    untrusted_cert = Path(temp_dir) / "untrusted_cert.pem"
    untrusted_key = Path(temp_dir) / "untrusted_key.pem"
    generate_self_signed_tls_cert(cert_path=untrusted_cert, key_path=untrusted_key, common_name="other-ca")

    class MockCloudHTTPSHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(201)
            self.end_headers()
            self.wfile.write(b'{"status": "STORED"}')

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), MockCloudHTTPSHandler)
    server_port = server.server_address[1]

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Initialize client trusting ONLY the untrusted_cert
        client = CloudForwardingClient(
            cloud_url=f"https://127.0.0.1:{server_port}",
            ca_cert_path=str(untrusted_cert),
            timeout_seconds=5.0,
        )
        msg = {"event_id": "tls_reject_01", "flow_id": "crit_flow"}
        res = client.forward_telemetry(msg)

        # Verification must FAIL, delivery must be False, message buffered in outage queue
        assert res.delivered is False
        assert res.status == CloudForwardStatus.QUEUED_FOR_CLOUD
        assert any(term in res.detail for term in ("CERTIFICATE_VERIFY_FAILED", "certificate verify failed", "Connection failed"))
        assert client.queue_size == 1
    finally:
        server.shutdown()


def test_tls_certificate_san_and_hostnames():
    """Verify that cloud TLS certificate contains required SANs matching connection targets."""
    from cryptography import x509
    from qeris.s2.certs import ensure_cloud_tls_certs

    cert_path, _ = ensure_cloud_tls_certs()
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_names = san_ext.value

    dns_names = [name.value for name in san_names if isinstance(name, x509.DNSName)]
    ip_addresses = [str(name.value) for name in san_names if isinstance(name, x509.IPAddress)]

    assert "localhost" in dns_names
    assert "qeris-cloud" in dns_names
    assert "qeris-gateway" in dns_names
    assert "127.0.0.1" in ip_addresses


def test_docker_compose_tls_and_admin_security_config():
    """Verify that docker-compose.yml uses HTTPS, enables SSL on cloud, and does not hardcode admin secret."""
    from pathlib import Path
    compose_path = Path(__file__).resolve().parent.parent.parent.parent / "docker-compose.yml"
    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Must use HTTPS for cloud URL
    assert "QERIS_CLOUD_URL=https://qeris-cloud:8001" in content
    # Cloud must run uvicorn with SSL certfile and keyfile
    assert "--ssl-certfile=/app/qeris/s2/certs/cloud_cert.pem" in content
    assert "--ssl-keyfile=/app/qeris/s2/certs/cloud_key.pem" in content
    # Healthcheck must use HTTPS curl
    assert "https://localhost:8001/api/v1/cloud/health" in content
    # Admin API key must use environment variable substitution, not hardcoded secret
    assert "QERIS_ADMIN_API_KEY=${QERIS_ADMIN_API_KEY}" in content
    assert "qeris-admin-key-2026" not in content


