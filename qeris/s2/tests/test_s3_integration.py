"""
Unit Tests for S3 Security State-Machine and Recovery Integration
"""
import pytest
from qeris.s2.s3_adapter import S3IntegrationAdapter

def test_s3_adapter_allow_processing():
    adapter = S3IntegrationAdapter()
    res = adapter.process_decision(
        device_id="device_002",
        flow_id="emergency_stop",
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        requested_mode="PQC",
        policy_version=1,
        initial_decision="ALLOW",
        reason="Policy criteria satisfied",
        authority_id="QERIS-GATEWAY",
        device_best_mode="PQC",
    )

    assert res["final_decision"] == "ALLOW"
    assert res["close_session"] is False

def test_s3_adapter_downgrade_rejection():
    adapter = S3IntegrationAdapter()
    res = adapter.process_decision(
        device_id="device_002",
        flow_id="emergency_stop",
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        requested_mode="CLASSICAL",
        policy_version=1,
        initial_decision="REJECT",
        reason="Below security floor",
        authority_id="QERIS-GATEWAY",
        device_best_mode="PQC",
    )

    assert res["final_decision"] in ("REJECT", "FLOOR_UNREACHABLE")
    assert res["close_session"] is True
    assert res["cause_label"] == "security_failure"

def test_s3_adapter_unknown_authority_treated_as_security_failure():
    adapter = S3IntegrationAdapter()
    res = adapter.process_decision(
        device_id="device_002",
        flow_id="emergency_stop",
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        requested_mode="PQC",
        policy_version=1,
        initial_decision="ALLOW",
        reason="OK",
        authority_id="UNTRUSTED_ROGUE_AUTHORITY",
    )

    # S3 tightens ALLOW to REJECT because authority is untrusted!
    assert res["final_decision"] in ("REJECT", "FLOOR_UNREACHABLE")
    assert res["close_session"] is True
