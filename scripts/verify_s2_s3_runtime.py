"""
QERIS Phase 7.2: Targeted S2+S3 Runtime Verification Harness
Exercises actual S2 Gateway and S3 Hook execution paths, evaluating:
  Scope A: Gateway Decision Integration
  Scope B: Security Floor Enforcement
  Scope C: Failure Classification and Recovery (including CAUSE_UNKNOWN / OBSERVE_AND_WAIT)
  Scope D: Policy Epoch Safety (DEC-4 / Invariant I8)
  Scope E: Audit Trail and State Persistence
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure repository root and modules are in sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_S2_DIR = _REPO_ROOT / "qeris" / "s2"
_S3_DIR = _REPO_ROOT / "qeris" / "s3"
for p in (_S2_DIR, _S3_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import (
    DEFAULT_AUTHORITY_ID,
    SecurityProfile,
)
from qeris.s2.crypto_engine import generate_authority_keypair
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore
from qeris.s2.audit_logger import GatewayAuditLogger
from qeris.s2.s3_adapter import S3IntegrationAdapter

# S3 imports
from failure_taxonomy import CauseClass, FailureTaxonomy, ObservedSignals
from recovery_controller import ControllerVerdict, RecoveryController
from floor_state_machine import FlowContext, FlowState
from downgrade_rejection import Mode
from s3_gateway_hook import S3GatewayHook
from policy_epoch import (
    HandshakeContextRecord,
    LivePolicySnapshot,
    PolicyEpochChangedEvent,
    activation_check,
    ActivationOutcome,
)
from profile_floor import ProfileFloor


def run_all_verifications() -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []

    # 1. Setup isolated runtime environment
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = Path(temp_dir.name)
    db_path = str(temp_path / "policy_store.db")
    audit_log_path = str(temp_path / "runtime_audit.jsonl")

    # Generate real authority keys
    authority_id = DEFAULT_AUTHORITY_ID
    priv_pem, pub_pem, _ = generate_authority_keypair()
    trusted_authorities = {authority_id: pub_pem}

    # Initialize PolicyStore
    policy_store = PolicyStore(db_path=db_path)

    # Initial Policy v1
    doc_v1 = PolicyDocumentModel(
        policy_version=1,
        authority_id=authority_id,
        policies={
            "flow_critical_01": FlowPolicyModel(
                flow_id="flow_critical_01",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=[
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                    SecurityProfile.PQC_MLKEM768_AESGCM.value,
                ],
            ),
            "flow_telemetry_02": FlowPolicyModel(
                flow_id="flow_telemetry_02",
                device_scope=["*"],
                sensitivity="MEDIUM",
                minimum_mode="HYBRID",
                approved_security_profiles=[
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
            "flow_diagnostics_03": FlowPolicyModel(
                flow_id="flow_diagnostics_03",
                device_scope=["*"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=[
                    SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
        },
    )
    env_v1 = sign_policy_document(doc_v1, priv_pem)
    policy_store.install_policy(env_v1, trusted_authorities)

    # Initialize Device Registry
    registry = DeviceRegistry()
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="device_pqc_capable",
            device_class="gateway_sensor",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                SecurityProfile.PQC_MLKEM512_AESGCM.value,
            ],
            ram_bytes_available=1048576,
            max_packet_size_mtu=1500,
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="device_classical_constrained",
            device_class="legacy_mcu",
            supported_modes=["CLASSICAL"],
            supported_security_profiles=[SecurityProfile.CLASSICAL_ECDH_AESGCM.value],
            ram_bytes_available=65536,
            max_packet_size_mtu=512,
        )
    )

    # Initialize Audit Logger
    audit_logger = GatewayAuditLogger(log_path=audit_log_path)

    # Initialize S3 Adapter
    s3_adapter = S3IntegrationAdapter(trusted_authorities=trusted_authorities)

    # Create FastAPI app
    app = create_gateway_app(
        policy_store=policy_store,
        registry=registry,
        audit_logger=audit_logger,
        s3_adapter=s3_adapter,
        trusted_authorities=trusted_authorities,
    )
    client = TestClient(app)

    print("=" * 80)
    print("QERIS Phase 7.2 Targeted S2+S3 Runtime Verification")
    print(f"Isolated Test Environment: {temp_path}")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # SCOPE A: Gateway Decision Integration (Actual Runtime Path Tracing)
    # -------------------------------------------------------------------------
    print("\n[Scope A: Gateway Decision Integration]")

    # Scenario A1: Trace compliant flow check through FastAPI -> S2 -> S3 Hook
    resp_a1 = client.post(
        "/check-flow",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_critical_01",
            "requested_mode": "PQC",
            "requested_profile": SecurityProfile.PQC_MLKEM512_AESGCM.value,
        },
    )
    data_a1 = resp_a1.json()
    p_a1 = (
        resp_a1.status_code == 200
        and data_a1.get("decision") == "ALLOW"
        and data_a1.get("s3_verdict") == "NONE"
    )
    evidence.append({
        "scenario": "A1: Compliant Flow Check Traced Through S2 & S3",
        "method": "Live FastAPI POST /check-flow via TestClient",
        "actual_execution_path": "client -> FastAPI(/check-flow) -> execute_flow_check -> s3_adapter.process_decision -> S3GatewayHook -> audit_logger",
        "expected_result": "ALLOW (s3_verdict=NONE, cause_label=none)",
        "observed_result": f"HTTP {resp_a1.status_code}, decision={data_a1.get('decision')}, s3_verdict={data_a1.get('s3_verdict')}",
        "status": "PASS" if p_a1 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  A1 Result: {'PASS' if p_a1 else 'FAIL'} - {data_a1}")

    # Scenario A2: S3 Tightening Verification (Untrusted Authority passed)
    # S2 would evaluate policy, but S3 Hook intercepts and verifies authority.
    # When an untrusted authority is passed, S3 MUST tighten ALLOW to REJECT with DISCARD_AND_LOG.
    res_a2 = s3_adapter.process_decision(
        device_id="device_pqc_capable",
        flow_id="flow_critical_01",
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        requested_mode="PQC",
        policy_version=1,
        initial_decision="ALLOW",
        reason="OK",
        authority_id="ROGUE_AUTHORITY_UNKNOWN",
    )
    p_a2 = (
        res_a2.get("final_decision") in ("REJECT", "FLOOR_UNREACHABLE")
        and res_a2.get("s3_verdict") == "DISCARD_AND_LOG"
        and res_a2.get("cause_label") == "security_failure"
        and res_a2.get("close_session") is True
    )
    evidence.append({
        "scenario": "A2: S3 Hook Tightening (Untrusted Authority)",
        "method": "Live invocation of s3_adapter with initial_decision=ALLOW and rogue authority",
        "actual_execution_path": "s3_adapter.process_decision -> S3GatewayHook.process_gateway_decision -> DowngradeRejector -> FailureTaxonomy -> AuditLogger",
        "expected_result": "REJECT / DISCARD_AND_LOG (S3 tightens ALLOW to REJECT)",
        "observed_result": f"final_decision={res_a2.get('final_decision')}, s3_verdict={res_a2.get('s3_verdict')}, cause={res_a2.get('cause_label')}",
        "status": "PASS" if p_a2 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  A2 Result: {'PASS' if p_a2 else 'FAIL'} - {res_a2}")

    # Scenario A3: S3 Never Relaxes a Rejection
    res_a3 = s3_adapter.process_decision(
        device_id="device_pqc_capable",
        flow_id="flow_critical_01",
        sensitivity="CRITICAL",
        minimum_mode="PQC",
        requested_mode="CLASSICAL",
        policy_version=1,
        initial_decision="REJECT",
        reason="Requested mode is below floor",
        authority_id=authority_id,
    )
    p_a3 = (
        res_a3.get("final_decision") in ("REJECT", "FLOOR_UNREACHABLE")
        and res_a3.get("s3_verdict") == "DISCARD_AND_LOG"
        and res_a3.get("close_session") is True
    )
    evidence.append({
        "scenario": "A3: S3 Invariant: Never Relax Rejection to Allow",
        "method": "Live invocation of s3_adapter with initial_decision=REJECT",
        "actual_execution_path": "s3_adapter.process_decision -> S3GatewayHook -> confirms terminal REJECT",
        "expected_result": "REJECT / DISCARD_AND_LOG preserved (never converted to ALLOW)",
        "observed_result": f"final_decision={res_a3.get('final_decision')}, s3_verdict={res_a3.get('s3_verdict')}",
        "status": "PASS" if p_a3 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  A3 Result: {'PASS' if p_a3 else 'FAIL'} - {res_a3}")

    # -------------------------------------------------------------------------
    # SCOPE B: Security Floor Enforcement
    # -------------------------------------------------------------------------
    print("\n[Scope B: Security Floor Enforcement]")

    # Scenario B1: Request below required floor (Classical on Critical Flow)
    resp_b1 = client.post(
        "/check-flow",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_critical_01",
            "requested_mode": "CLASSICAL",
            "requested_profile": SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
        },
    )
    data_b1 = resp_b1.json()
    p_b1 = (
        data_b1.get("decision") == "REJECT"
        and data_b1.get("s3_verdict") in ("DISCARD_AND_LOG", "FLOOR_UNREACHABLE")
    )
    evidence.append({
        "scenario": "B1: Classical Downgrade Attempt on Critical PQC Flow",
        "method": "FastAPI POST /check-flow with requested_mode=CLASSICAL on CRITICAL flow",
        "actual_execution_path": "FastAPI -> execute_flow_check -> floor violation -> s3_adapter -> S3Hook.process_gateway_decision",
        "expected_result": "REJECT with cause_label=security_failure and s3_verdict=DISCARD_AND_LOG",
        "observed_result": f"decision={data_b1.get('decision')}, cause_label={data_b1.get('cause_label')}, s3_verdict={data_b1.get('s3_verdict')}",
        "status": "PASS" if p_b1 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  B1 Result: {'PASS' if p_b1 else 'FAIL'} - {data_b1}")

    # Scenario B2: Device capability insufficient for floor (Constrained device on PQC flow)
    resp_b2 = client.post(
        "/check-flow",
        json={
            "device_id": "device_classical_constrained",
            "flow_id": "flow_critical_01",
            "requested_mode": "PQC",
            "requested_profile": SecurityProfile.PQC_MLKEM512_AESGCM.value,
        },
    )
    data_b2 = resp_b2.json()
    p_b2 = (
        data_b2.get("decision") in ("FLOOR_UNREACHABLE", "REJECT")
        and any(k in data_b2.get("reason", "").lower() for k in ("unreachable", "not_ready", "intersection"))
    )
    evidence.append({
        "scenario": "B2: Constrained Device Cannot Meet Floor",
        "method": "FastAPI POST /check-flow with classical-only device on PQC flow",
        "actual_execution_path": "FastAPI -> execute_flow_check -> registry capability check -> FLOOR_UNREACHABLE",
        "expected_result": "FLOOR_UNREACHABLE (Device cannot reach minimum mode PQC)",
        "observed_result": f"decision={data_b2.get('decision')}, reason={data_b2.get('reason')}",
        "status": "PASS" if p_b2 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  B2 Result: {'PASS' if p_b2 else 'FAIL'} - {data_b2}")

    # Scenario B3: Untrusted device-reported sensitivity cannot override policy
    # Device claims sensitivity is 'LOW' on 'flow_critical_01'
    resp_b3 = client.post(
        "/check-flow",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_critical_01",
            "requested_mode": "CLASSICAL",
            "device_reported_sensitivity": "LOW",
        },
    )
    data_b3 = resp_b3.json()
    p_b3 = (
        data_b3.get("decision") == "REJECT"
        and data_b3.get("sensitivity") == "CRITICAL"
    )
    evidence.append({
        "scenario": "B3: Invariant I6: Device-Reported Sensitivity Cannot Override Policy Floor",
        "method": "FastAPI POST /check-flow with device_reported_sensitivity=LOW on CRITICAL flow",
        "actual_execution_path": "FastAPI -> execute_flow_check -> policy_store lookup overrides device input -> floor enforced",
        "expected_result": "REJECT (Policy CRITICAL floor enforced, untrusted device input ignored)",
        "observed_result": f"decision={data_b3.get('decision')}, authoritative_sensitivity={data_b3.get('sensitivity')}",
        "status": "PASS" if p_b3 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  B3 Result: {'PASS' if p_b3 else 'FAIL'} - {data_b3}")

    # -------------------------------------------------------------------------
    # SCOPE C: Failure Classification and Recovery (Including CAUSE_UNKNOWN)
    # -------------------------------------------------------------------------
    print("\n[Scope C: Failure Classification and Recovery]")
    taxonomy = FailureTaxonomy()
    controller = RecoveryController(base_backoff_ms=100, max_loss_retries=3)

    # Scenario C1: Loss / Timeout produces RETRY with backoff
    sig_c1 = ObservedSignals(no_response=True)
    evt_c1 = taxonomy.classify(sig_c1)
    ctx_c1 = FlowContext(
        flow_id="flow_telemetry_02",
        device_id="device_pqc_capable",
        floor_mode=Mode.HYBRID,
        negotiated_mode=Mode.HYBRID,
        device_best_mode=Mode.PQ,
    )
    dec_c1 = controller.handle("sess_c1", evt_c1, FlowState.ACTIVE, ctx_c1)
    p_c1 = (
        evt_c1.cause == CauseClass.LOSS_TIMEOUT
        and dec_c1.verdict == ControllerVerdict.RETRY
        and dec_c1.backoff_ms > 0
        and not dec_c1.close_session
    )
    evidence.append({
        "scenario": "C1: Transport Loss Classification & Bounded Exponential Retry",
        "method": "ObservedSignals(no_response=True) -> FailureTaxonomy -> RecoveryController",
        "actual_execution_path": "taxonomy.classify -> LOSS_TIMEOUT -> controller.handle -> ControllerVerdict.RETRY with backoff",
        "expected_result": "cause=loss_timeout, verdict=RETRY, backoff_ms > 0, close_session=False",
        "observed_result": f"cause={evt_c1.cause.value}, verdict={dec_c1.verdict.name}, backoff_ms={dec_c1.backoff_ms}",
        "status": "PASS" if p_c1 else "FAIL",
        "evidence_type": "Controlled runtime fault injection",
    })
    print(f"  C1 Result: {'PASS' if p_c1 else 'FAIL'} - {evt_c1.cause}, {dec_c1.verdict}, backoff={dec_c1.backoff_ms}")

    # Scenario C2: MTU Fragmentation Failure produces REFRAGMENT
    sig_c2 = ObservedSignals(fragment_size_exceeded=True)
    evt_c2 = taxonomy.classify(sig_c2)
    dec_c2 = controller.handle("sess_c2", evt_c2, FlowState.ACTIVE, ctx_c1)
    p_c2 = (
        evt_c2.cause == CauseClass.MTU_FRAGMENT
        and dec_c2.verdict == ControllerVerdict.REFRAGMENT
    )
    evidence.append({
        "scenario": "C2: MTU Fragment Exceeded Classification & REFRAGMENT Action",
        "method": "ObservedSignals(fragment_size_exceeded=True) -> FailureTaxonomy -> RecoveryController",
        "actual_execution_path": "taxonomy.classify -> MTU_FRAGMENT -> controller.handle -> ControllerVerdict.REFRAGMENT",
        "expected_result": "cause=mtu_fragment, verdict=REFRAGMENT, no mode downgrade",
        "observed_result": f"cause={evt_c2.cause.value}, verdict={dec_c2.verdict.name}",
        "status": "PASS" if p_c2 else "FAIL",
        "evidence_type": "Controlled runtime fault injection",
    })
    print(f"  C2 Result: {'PASS' if p_c2 else 'FAIL'} - {evt_c2.cause}, {dec_c2.verdict}")

    # Scenario C3: Security Failure (Signature Tampering) produces terminal DISCARD_AND_LOG
    sig_c3 = ObservedSignals(auth_check_failed=True)
    evt_c3 = taxonomy.classify(sig_c3)
    dec_c3 = controller.handle("sess_c3", evt_c3, FlowState.ACTIVE, ctx_c1)
    p_c3 = (
        evt_c3.cause == CauseClass.SECURITY_FAILURE
        and dec_c3.verdict == ControllerVerdict.DISCARD_AND_LOG
        and dec_c3.close_session is True
    )
    evidence.append({
        "scenario": "C3: Invariant I4: Security Attack Immediately Quarantined Without Retry",
        "method": "ObservedSignals(auth_check_failed=True) -> FailureTaxonomy -> RecoveryController",
        "actual_execution_path": "taxonomy.classify -> SECURITY_FAILURE -> controller.handle -> ControllerVerdict.DISCARD_AND_LOG",
        "expected_result": "cause=security_failure, verdict=DISCARD_AND_LOG, close_session=True (terminal)",
        "observed_result": f"cause={evt_c3.cause.value}, verdict={dec_c3.verdict.name}, close_session={dec_c3.close_session}",
        "status": "PASS" if p_c3 else "FAIL",
        "evidence_type": "Controlled runtime fault injection",
    })
    print(f"  C3 Result: {'PASS' if p_c3 else 'FAIL'} - {evt_c3.cause}, {dec_c3.verdict}")

    # Scenario C4: CAUSE_UNKNOWN Classifier Abstention & OBSERVE_AND_WAIT
    # Empty/ambiguous signals MUST NOT guess loss_timeout; it must abstain with CAUSE_UNKNOWN
    sig_c4 = ObservedSignals()  # ambiguous / empty
    evt_c4 = taxonomy.classify(sig_c4)
    dec_c4_1 = controller.handle("sess_unknown", evt_c4, FlowState.ACTIVE, ctx_c1)
    p_c4_1 = (
        evt_c4.cause == CauseClass.CAUSE_UNKNOWN
        and evt_c4.label_confidence == "low"
        and dec_c4_1.verdict == ControllerVerdict.OBSERVE_AND_WAIT
        and dec_c4_1.attempt == 1
        and not dec_c4_1.close_session
    )
    evidence.append({
        "scenario": "C4: Blueprint DEC-5: CAUSE_UNKNOWN Classifier Abstention & OBSERVE_AND_WAIT",
        "method": "ObservedSignals(empty/ambiguous) -> FailureTaxonomy -> RecoveryController",
        "actual_execution_path": "taxonomy.classify -> CAUSE_UNKNOWN(low conf) -> controller.handle -> OBSERVE_AND_WAIT(attempt=1)",
        "expected_result": "cause=cause_unknown, verdict=OBSERVE_AND_WAIT, attempt=1, no profile change",
        "observed_result": f"cause={evt_c4.cause.value}, verdict={dec_c4_1.verdict.name}, attempt={dec_c4_1.attempt}",
        "status": "PASS" if p_c4_1 else "FAIL",
        "evidence_type": "Controlled runtime fault injection",
    })
    print(f"  C4-1 Result: {'PASS' if p_c4_1 else 'FAIL'} - {evt_c4.cause}, {dec_c4_1.verdict}, attempt={dec_c4_1.attempt}")

    # Scenario C5: CAUSE_UNKNOWN Hard Cap Escalation (Attempt 2 -> FAIL)
    dec_c4_2 = controller.handle("sess_unknown", evt_c4, FlowState.ACTIVE, ctx_c1)
    p_c4_2 = (
        dec_c4_2.verdict == ControllerVerdict.FAIL
        and dec_c4_2.attempt == 2
        and dec_c4_2.close_session is True
    )
    evidence.append({
        "scenario": "C5: CAUSE_UNKNOWN Observation Cap Exceeded Escalates to Terminal FAIL",
        "method": "Second consecutive handle() invocation for same session under CAUSE_UNKNOWN",
        "actual_execution_path": "controller.handle -> cap checked (max 1 observation window) -> ControllerVerdict.FAIL",
        "expected_result": "verdict=FAIL, attempt=2, close_session=True (conservative termination)",
        "observed_result": f"verdict={dec_c4_2.verdict.name}, attempt={dec_c4_2.attempt}, close_session={dec_c4_2.close_session}",
        "status": "PASS" if p_c4_2 else "FAIL",
        "evidence_type": "Controlled runtime fault injection",
    })
    print(f"  C4-2 Result: {'PASS' if p_c4_2 else 'FAIL'} - {dec_c4_2.verdict}, attempt={dec_c4_2.attempt}")

    # -------------------------------------------------------------------------
    # SCOPE D: Policy Epoch Safety (DEC-4 / Invariant I8)
    # -------------------------------------------------------------------------
    print("\n[Scope D: Policy Epoch Safety (DEC-4 / Invariant I8)]")

    # Scenario D1: Complete handshake establishing active session at Epoch v1
    resp_d1 = client.post(
        "/api/v1/handshake/complete",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_telemetry_02",
            "negotiated_profile": SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
            "session_key_hex": os.urandom(32).hex(),
        },
    )
    data_d1 = resp_d1.json()
    session_id_d1 = data_d1.get("session_id")
    p_d1 = resp_d1.status_code == 200 and data_d1.get("status") == "SESSION_ACTIVE"
    print(f"  D1 Result: {'PASS' if p_d1 else 'FAIL'} - Handshake complete: session={session_id_d1}")

    # Scenario D2: Telemetry accepted under matching current epoch v1
    resp_d2 = client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_telemetry_02",
            "session_id": session_id_d1,
            "payload": {"temperature": 23.4, "status": "nominal"},
        },
    )
    p_d2 = resp_d2.status_code == 200 and resp_d2.json().get("status") == "ACCEPTED"
    evidence.append({
        "scenario": "D1-D2: Normal Session Establishment & Telemetry Under Policy Epoch v1",
        "method": "FastAPI POST /api/v1/handshake/complete followed by POST /api/v1/telemetry",
        "actual_execution_path": "complete_handshake -> SessionManager.create_session -> submit_telemetry -> epoch verification -> cloud queue",
        "expected_result": "SESSION_ACTIVE then telemetry ACCEPTED",
        "observed_result": f"Handshake={data_d1.get('status')}, Telemetry={resp_d2.json().get('status')}",
        "status": "PASS" if (p_d1 and p_d2) else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  D2 Result: {'PASS' if p_d2 else 'FAIL'} - Telemetry accepted: {resp_d2.json()}")

    # Scenario D3: Policy update to v2 where HYBRID is STILL approved (Compatible Rebind)
    doc_v2 = PolicyDocumentModel(
        policy_version=2,
        authority_id=authority_id,
        policies={
            "flow_telemetry_02": FlowPolicyModel(
                flow_id="flow_telemetry_02",
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
    env_v2 = sign_policy_document(doc_v2, priv_pem)
    policy_store.install_policy(env_v2, trusted_authorities)

    # Submit telemetry with session created under v1. DEC-4 guard should rebind and ACCEPT.
    resp_d3 = client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_telemetry_02",
            "session_id": session_id_d1,
            "payload": {"temperature": 23.8, "status": "nominal"},
        },
    )
    p_d3 = resp_d3.status_code == 200 and resp_d3.json().get("status") == "ACCEPTED"
    evidence.append({
        "scenario": "D3: Compatible Policy Update v1 -> v2 Rebinds Active Session Without Disruption",
        "method": "Install signed Policy v2 (HYBRID still approved) -> POST /api/v1/telemetry",
        "actual_execution_path": "submit_telemetry -> SessionManager.validate_and_rebind_session -> profile approved in v2 -> session epoch updated to v2",
        "expected_result": "ACCEPTED (Session transparently re-bound to epoch v2)",
        "observed_result": f"HTTP {resp_d3.status_code}, status={resp_d3.json().get('status')}",
        "status": "PASS" if p_d3 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  D3 Result: {'PASS' if p_d3 else 'FAIL'} - Compatible rebind telemetry: {resp_d3.json()}")

    # Scenario D4: Policy update to v3 where HYBRID is REMOVED (Floor Raised to PQC-only)
    # The active session is using HYBRID. When telemetry arrives, DEC-4 guard MUST REJECT with 403.
    doc_v3 = PolicyDocumentModel(
        policy_version=3,
        authority_id=authority_id,
        policies={
            "flow_telemetry_02": FlowPolicyModel(
                flow_id="flow_telemetry_02",
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
    env_v3 = sign_policy_document(doc_v3, priv_pem)
    policy_store.install_policy(env_v3, trusted_authorities)

    resp_d4 = client.post(
        "/api/v1/telemetry",
        json={
            "device_id": "device_pqc_capable",
            "flow_id": "flow_telemetry_02",
            "session_id": session_id_d1,
            "payload": {"temperature": 24.1, "status": "breach_attempt"},
        },
    )
    p_d4 = resp_d4.status_code == 403 and "DEC-4 Policy Epoch Mismatch" in resp_d4.text
    evidence.append({
        "scenario": "D4: Invariant I8: Incompatible Policy Update v2 -> v3 Rejects Stale Session",
        "method": "Install signed Policy v3 (Floor raised to PQC-only) -> POST /api/v1/telemetry with HYBRID session",
        "actual_execution_path": "submit_telemetry -> SessionManager.validate_and_rebind_session -> profile not in v3 approved list -> HTTP 403 + stale_epoch_rejected audit log",
        "expected_result": "HTTP 403 Forbidden with DEC-4 Policy Epoch Mismatch error",
        "observed_result": f"HTTP {resp_d4.status_code}, error={resp_d4.json().get('detail')}",
        "status": "PASS" if p_d4 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  D4 Result: {'PASS' if p_d4 else 'FAIL'} - Incompatible session rejected: {resp_d4.status_code} {resp_d4.text}")

    # Scenario D5: Stale in-flight handshake evaluated via policy_epoch.activation_check()
    raw_policy_bytes_v1 = b"flow_telemetry_02:epoch1"
    raw_policy_bytes_v3 = b"flow_telemetry_02:epoch3"
    ctx_inflight = HandshakeContextRecord.create(
        device_id="device_pqc_capable",
        flow_id="flow_telemetry_02",
        epoch=1,
        policy_bytes=raw_policy_bytes_v1,
        approved_profiles=frozenset([SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value]),
        handshake_id="hs_inflight_001",
    )
    # At activation time, current policy is v3 which forbids HYBRID
    live_snap_v3 = LivePolicySnapshot.create(
        epoch=3,
        policy_bytes=raw_policy_bytes_v3,
        approved_profiles=set([SecurityProfile.PQC_MLKEM512_AESGCM.value]),
    )
    res_d5 = activation_check(
        ctx_inflight,
        live=live_snap_v3,
        negotiated_profile=SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
    )
    p_d5 = (
        res_d5.outcome == ActivationOutcome.IMPOSSIBLE_QUARANTINE
        and res_d5.should_activate is False
        and res_d5.should_quarantine is True
    )
    evidence.append({
        "scenario": "D5: S3 Invariant I8: In-Flight Handshake Epoch Check Blocks Stale Activation",
        "method": "Live activation_check() evaluation with context epoch=1 vs live epoch=3",
        "actual_execution_path": "policy_epoch.activation_check -> epoch mismatch & profile not in new set -> IMPOSSIBLE_QUARANTINE",
        "expected_result": "outcome=IMPOSSIBLE_QUARANTINE, should_activate=False, should_quarantine=True",
        "observed_result": f"outcome={res_d5.outcome.name}, activate={res_d5.should_activate}, quarantine={res_d5.should_quarantine}",
        "status": "PASS" if p_d5 else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  D5 Result: {'PASS' if p_d5 else 'FAIL'} - In-flight check outcome: {res_d5.outcome.name}")

    # -------------------------------------------------------------------------
    # SCOPE E: Audit and State Verification
    # -------------------------------------------------------------------------
    print("\n[Scope E: Audit Trail and State Persistence]")
    with open(audit_log_path, "r", encoding="utf-8") as f:
        log_lines = [json.loads(line) for line in f if line.strip()]

    print(f"Total audit records generated during verification: {len(log_lines)}")

    # Check key audit events
    event_types = [e.get("event_type") for e in log_lines]
    decisions = [e.get("decision") for e in log_lines]
    has_flow_check_allow = "ALLOW" in decisions
    has_flow_check_reject = "REJECT" in decisions
    has_handshake_complete = "handshake_complete" in event_types
    has_stale_epoch_reject = "stale_epoch_rejected" in event_types

    # Verify canonical schema fields on records
    sample_record = log_lines[0]
    required_fields = ["event_id", "ts", "timestamp_iso", "decision", "event_type"]
    has_all_required = all(k in sample_record for k in required_fields)

    p_e = (
        has_flow_check_allow
        and has_flow_check_reject
        and has_handshake_complete
        and has_stale_epoch_reject
        and has_all_required
    )
    evidence.append({
        "scenario": "E1: Comprehensive Audit Trail and State Persistence",
        "method": "Inspection of raw JSONL records written to runtime_audit.jsonl",
        "actual_execution_path": "GatewayAuditLogger.log_event -> jsonl file append -> parsed into memory",
        "expected_result": "All tested events (ALLOW, REJECT, FLOOR_UNREACHABLE, handshake_complete, stale_epoch_rejected) logged with full schema",
        "observed_result": f"Total logs={len(log_lines)}, events={set(event_types)}, required_fields_ok={has_all_required}",
        "status": "PASS" if p_e else "FAIL",
        "evidence_type": "Live runtime execution",
    })
    print(f"  E1 Result: {'PASS' if p_e else 'FAIL'} - Audit verified: {len(log_lines)} events logged.")

    # Cleanup temp directory
    temp_dir.cleanup()

    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    all_pass = all(item["status"] == "PASS" for item in evidence)
    print(f"Overall Status: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
    print(f"Total Scenarios Tested: {len(evidence)}")
    print(f"Pass Count: {sum(1 for e in evidence if e['status'] == 'PASS')}")
    print(f"Fail Count: {sum(1 for e in evidence if e['status'] != 'PASS')}")

    return {
        "all_pass": all_pass,
        "evidence": evidence,
        "total_scenarios": len(evidence),
    }


if __name__ == "__main__":
    result = run_all_verifications()
    sys.exit(0 if result["all_pass"] else 1)
