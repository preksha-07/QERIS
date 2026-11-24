"""
Unit Tests for Device Capability Registry and Deterministic Readiness
"""
import os
import pytest
from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.policy_schema import FlowPolicyModel
from qeris.s2.readiness import ReadinessStatus, evaluate_readiness

def test_registry_crud(temp_dir):
    db_path = os.path.join(temp_dir, "test_reg.db")
    reg = DeviceRegistry(db_path=db_path)

    dev = DeviceCapabilityProfile(
        device_id="dev-sensor-01",
        device_class="esp32_constrained",
        supported_modes=["CLASSICAL", "HYBRID"],
        supported_security_profiles=["CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM"],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=1280,
    )
    reg.register_device(dev)

    fetched = reg.get_device("dev-sensor-01")
    assert fetched is not None
    assert fetched.device_id == "dev-sensor-01"
    assert fetched.device_class == "esp32_constrained"
    assert fetched.supported_modes == ["CLASSICAL", "HYBRID"]

    # Quarantine toggle
    reg.set_quarantine("dev-sensor-01", True, "Tamper detected")
    quarantined = reg.get_device("dev-sensor-01")
    assert quarantined.quarantined is True
    assert quarantined.quarantine_reason == "Tamper detected"

def test_readiness_ready():
    device = DeviceCapabilityProfile(
        device_id="dev_pqc_capable",
        supported_security_profiles=["CLASSICAL_ECDH_AESGCM", "PQC_MLKEM512_AESGCM"],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=2000,
    )
    flow = FlowPolicyModel(
        flow_id="critical_telemetry",
        device_scope=["*"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM512_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.READY
    assert res.recommended_profile == "PQC_MLKEM512_AESGCM"
    assert res.is_executable is True
    assert res.requires_fragmentation is False

def test_readiness_not_ready_no_profile_intersection():
    device = DeviceCapabilityProfile(
        device_id="dev_legacy",
        supported_security_profiles=["CLASSICAL_ECDH_AESGCM"],
    )
    flow = FlowPolicyModel(
        flow_id="crit_flow",
        device_scope=["*"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM512_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.NOT_READY
    assert res.is_executable is False
    assert any("No security profile intersection" in r for r in res.reasons)

def test_readiness_not_ready_quarantined():
    device = DeviceCapabilityProfile(
        device_id="dev_compromised",
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
        quarantined=True,
        quarantine_reason="Hardware integrity warning",
    )
    flow = FlowPolicyModel(
        flow_id="crit_flow",
        device_scope=["*"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM512_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.NOT_READY
    assert any("quarantined" in r for r in res.reasons)

def test_readiness_not_ready_out_of_device_scope():
    device = DeviceCapabilityProfile(
        device_id="dev_unauthorized_node",
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
    )
    flow = FlowPolicyModel(
        flow_id="restricted_flow",
        device_scope=["dev_authorized_node_1", "dev_authorized_node_2"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM512_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.NOT_READY
    assert any("device scope" in r for r in res.reasons)

def test_readiness_partially_ready_fragmentation_required():
    device = DeviceCapabilityProfile(
        device_id="dev_small_mtu",
        supported_security_profiles=["PQC_MLKEM512_AESGCM"],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=1280,  # Below PQC wire size 1820
    )
    flow = FlowPolicyModel(
        flow_id="crit_flow",
        device_scope=["*"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM512_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.PARTIALLY_READY
    assert res.requires_fragmentation is True
    assert res.is_executable is True

def test_readiness_not_ready_insufficient_ram():
    device = DeviceCapabilityProfile(
        device_id="dev_tiny_ram",
        supported_security_profiles=["PQC_MLKEM1024_AESGCM"],
        ram_bytes_available=16 * 1024,  # 16 KB is less than 96 KB required for ML-KEM-1024
    )
    flow = FlowPolicyModel(
        flow_id="ultra_pqc_flow",
        device_scope=["*"],
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        approved_security_profiles=["PQC_MLKEM1024_AESGCM"],
    )

    res = evaluate_readiness(device, flow)
    assert res.status == ReadinessStatus.NOT_READY
    assert any("RAM" in r for r in res.reasons)
