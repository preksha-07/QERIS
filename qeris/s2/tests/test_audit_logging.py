"""
Unit Tests for Gateway Structured Audit Logging
"""
import io
import json
import pytest
from qeris.s2.audit_logger import GatewayAuditLogger

def test_audit_logger_fields_and_format():
    sink = io.StringIO()
    logger = GatewayAuditLogger(sink=sink)

    record = logger.log_event(
        "policy_verified",
        device_id="dev_001",
        flow_id="emergency_stop",
        decision="ALLOW",
        reason="Security floor satisfied",
        sensitivity="CRITICAL",
        security_profile="PQC_MLKEM512_AESGCM",
        mode="PQC",
        policy_version=2,
        policy_digest="a" * 64,
        session_id="sess_123",
        readiness_status="READY",
    )

    # Check record fields
    assert "event_id" in record
    assert "ts" in record
    assert "timestamp_iso" in record
    assert record["event_type"] == "policy_verified"
    assert record["decision"] == "ALLOW"
    assert record["sensitivity"] == "CRITICAL"
    assert record["policy_version"] == 2
    assert record["policy_digest"] == "a" * 64

    # Check output line
    output = sink.getvalue().strip()
    parsed = json.loads(output)
    assert parsed["event_id"] == record["event_id"]
    assert parsed["device_id"] == "dev_001"

def test_audit_logger_redaction_no_secrets():
    sink = io.StringIO()
    logger = GatewayAuditLogger(sink=sink)

    fake_secret = "SECRET_PRIVATE_KEY_BYTES_OR_TOKEN"
    logger.log_event(
        "handshake_complete",
        device_id="dev_001",
        flow_id="crit_flow",
        decision="ALLOW",
        reason="Success",
        details={"info": "standard metadata"},
    )

    output = sink.getvalue()
    assert fake_secret not in output
    assert "private_key" not in output
    assert "session_key" not in output


def test_audit_logger_recursive_secret_redaction():
    """Confirms that sensitive keys inside details dict are masked automatically as [REDACTED]."""
    sink = io.StringIO()
    logger = GatewayAuditLogger(sink=sink)

    logger.log_event(
        "auth_event",
        device_id="dev_001",
        flow_id="crit_flow",
        decision="ALLOW",
        reason="Success",
        details={
            "session_key": "raw_32_byte_secret",
            "password": "super_secret_admin",
            "nested_context": {
                "private_key": "mldsa_priv_pem_here",
                "auth_token": "bearer_token_123",
                "safe_info": "unclassified_metric",
            },
        },
    )

    output = sink.getvalue()
    assert "raw_32_byte_secret" not in output
    assert "super_secret_admin" not in output
    assert "mldsa_priv_pem_here" not in output
    assert "bearer_token_123" not in output

    parsed = json.loads(output)
    details = parsed["details"]
    assert details["session_key"] == "[REDACTED]"
    assert details["password"] == "[REDACTED]"
    assert details["nested_context"]["private_key"] == "[REDACTED]"
    assert details["nested_context"]["auth_token"] == "[REDACTED]"
    assert details["nested_context"]["safe_info"] == "unclassified_metric"

