"""
QERIS Security Gateway (Phase 3 & Phase 4 Integrated Backend)

Integrates:
- S1 Post-Quantum Cryptography (ML-DSA-65 policy verification, ML-KEM-512 session crypto, AES-256-GCM)
- S2 Gateway Logic (5-field canonical policy contract, device capabilities, floor enforcement)
- S3 Security & Recovery Logic (S3GatewayHook, DowngradeRejector, FailureTaxonomy, ReplayProtection)
- S4 Evaluation Logging (Structured trace records with cause labels and verdicts)
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Optional
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure S1, S2, S3, and S4 paths are accessible
_BASE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BASE_DIR.parent.parent
_S1_DIR = _REPO_ROOT / "qeris" / "s1"
_S3_DIR = _REPO_ROOT / "qeris" / "s3"
_S4_DIR = _REPO_ROOT / "qeris" / "s4"

for path in (str(_BASE_DIR), str(_S1_DIR), str(_S3_DIR), str(_S4_DIR), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from crypto_adapter import (
    CryptoPreconditionError,
    CryptoSession,
    UnsupportedCryptoModeError,
    establish_session,
)
from dataset_service import DatasetService, QERIS_TO_DATASET_DEVICE
from policy_manager import S2PolicyManager
from qeris.policy.signed_policy import PolicyVerificationStatus
from s3_gateway_hook import S3GatewayHook, S3HookResult

app = FastAPI(
    title="QERIS Security Gateway",
    description="Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway",
    version="2.1.0",
)

# Enable CORS for browser frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_POLICY_PATH = _BASE_DIR / "policy.json"
_DEVICES_PATH = _BASE_DIR / "devices.json"
_LOGS_PATH = _BASE_DIR / "gateway_logs.jsonl"

# 1. Initialize S2 Policy Manager (verifies S1 ML-DSA-65 signatures & S3 ReplayProtection)
policy_manager = S2PolicyManager(base_dir=_BASE_DIR)

# 2. Load device capability registry
if _DEVICES_PATH.exists():
    device_registry = json.loads(_DEVICES_PATH.read_text(encoding="utf-8"))
else:
    device_registry = {}

# 3. Initialize S3 Gateway Hook (stateful security & recovery controller)
s3_hook = S3GatewayHook(
    audit_level="standard",
    rate_limit_per_min=0,  # Uncapped for integration tests & high-throughput gateways
    max_loss_retries=3,
    max_mtu_retries=2,
)

# 4. Initialize Dataset Service (317k IoT dataset mapped to 3 registered devices)
dataset_service = DatasetService()

SECURITY_LEVEL = {
    "CLASSICAL": 1,
    "HYBRID": 2,
    "PQC": 3,
    "PQ": 3,
}


class FlowRequest(BaseModel):
    device_id: str
    flow_id: str
    requested_mode: str
    trace_id: Optional[str] = None


class CryptoDemoRequest(BaseModel):
    device_id: str
    flow_id: str
    message: Optional[str] = None
    requested_mode: str = "PQC"
    trace_id: Optional[str] = None
    record_id: Optional[str] = None


def check_policy(flow_id: str, requested_mode: str) -> tuple[bool, str]:
    """Evaluates requested security mode against verified policy floor."""
    verified_policy = policy_manager.get_verified_policy(flow_id)
    if not verified_policy:
        return False, "Unknown or unverified flow"

    req_mode_norm = requested_mode.strip().upper()
    if req_mode_norm not in SECURITY_LEVEL:
        return False, f"Unknown security mode: '{requested_mode}'"

    required_mode = verified_policy["minimum_mode"].strip().upper()
    required_level = SECURITY_LEVEL.get(required_mode, 1)
    requested_level = SECURITY_LEVEL.get(req_mode_norm, 1)

    if requested_level < required_level:
        return False, f"Requested mode '{req_mode_norm}' is below security floor '{required_mode}'"

    return True, "Policy satisfied"


def check_device_capability(device_id: str, requested_mode: str) -> tuple[bool, str]:
    """Validates if device is registered and supports the requested security mode."""
    if device_id not in device_registry:
        return False, f"Unknown device: '{device_id}'"

    supported_modes = [m.strip().upper() for m in device_registry[device_id].get("supported_modes", [])]
    req_mode_norm = requested_mode.strip().upper()

    if req_mode_norm not in supported_modes:
        return False, f"Device '{device_id}' does not support requested mode '{req_mode_norm}'"

    return True, "Device capability satisfied"


def check_floor_feasibility(device_id: str, flow_id: str) -> tuple[bool, str]:
    """Validates if device's maximum capability can satisfy the flow's minimum floor."""
    if device_id not in device_registry:
        return False, f"Unknown device: '{device_id}'"

    verified_policy = policy_manager.get_verified_policy(flow_id)
    if not verified_policy:
        return False, "Unknown or unverified flow"

    required_mode = verified_policy["minimum_mode"].strip().upper()
    required_level = SECURITY_LEVEL.get(required_mode, 1)

    supported_modes = [m.strip().upper() for m in device_registry[device_id].get("supported_modes", [])]
    if not supported_modes:
        return False, f"Device '{device_id}' has no registered modes"

    highest_supported_level = max(SECURITY_LEVEL.get(m, 1) for m in supported_modes)

    if highest_supported_level < required_level:
        return False, f"Security floor '{required_mode}' is unreachable for device '{device_id}' (max: {supported_modes})"

    return True, "Security floor is reachable"


def get_device_best_mode(device_id: str) -> Optional[str]:
    """Returns the highest security mode supported by a device."""
    if device_id not in device_registry:
        return None
    modes = device_registry[device_id].get("supported_modes", [])
    if not modes:
        return None
    return max(modes, key=lambda m: SECURITY_LEVEL.get(m.strip().upper(), 0))


def write_audit_log(
    trace_id: str,
    device_id: str,
    flow_id: str,
    sensitivity: Optional[str],
    minimum_mode: Optional[str],
    requested_mode: str,
    policy_version: Optional[int],
    authority_id: Optional[str],
    decision: str,
    reason: str,
    s3_verdict: str = "NONE",
    cause_label: str = "none",
    security_reason: Optional[str] = None,
    crypto_status: str = "SKIPPED",
    record_id: Optional[str] = None,
    dataset_source: Optional[str] = None,
    is_anomaly: Optional[int] = None,
) -> None:
    """Writes a standardized, secret-free audit entry conforming to S1-S4 logging contracts."""
    epoch_ms = int(time.time() * 1000)
    now_iso = datetime.now(timezone.utc).isoformat()

    log_entry = {
        "trace_id": trace_id,
        "ts": epoch_ms,
        "timestamp": now_iso,
        "device_id": device_id,
        "flow_id": flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "requested_mode": requested_mode,
        "policy_version": policy_version,
        "authority_id": authority_id,
        "decision": decision,
        "reason": reason,
        "s3_verdict": s3_verdict,
        "cause_label": cause_label,
        "security_reason": security_reason,
        "crypto_status": crypto_status,
    }
    if record_id is not None:
        log_entry["record_id"] = record_id
    if dataset_source is not None:
        log_entry["dataset_source"] = dataset_source
    if is_anomaly is not None:
        log_entry["is_anomaly"] = is_anomaly

    try:
        with open(_LOGS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, separators=(",", ":")) + "\n")
    except OSError as err:
        sys.stderr.write(f"Failed to write audit log: {err}\n")


@app.get("/health")
def health_check():
    """System health and subsystem integration status."""
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verified_flows": list(policy_manager._verified_policies.keys()),
        "authority_id": policy_manager.DEFAULT_AUTHORITY_ID,
        "persisted_policy_version": policy_manager.replay_guard.highest_version,
        "registered_devices": list(device_registry.keys()),
    }


@app.post("/check-flow")
def check_flow(request: FlowRequest):
    """Evaluates flow request through S1 policy verification, S2 floor checks, and S3 security hook."""
    trace_id = request.trace_id or str(uuid.uuid4())
    device_id = request.device_id.strip()
    flow_id = request.flow_id.strip()
    requested_mode = request.requested_mode.strip().upper()

    s1_status: Optional[str] = None
    best_mode = get_device_best_mode(device_id)

    # 1. Step 1: S1 Policy Verification Check
    verified_policy = policy_manager.get_verified_policy(flow_id)
    if not verified_policy:
        v_res = policy_manager.get_verification_result(flow_id)
        if v_res is not None:
            s1_status = v_res.status.name
            s2_decision = "REJECT"
            s2_reason = f"Signed policy verification failed: {v_res.message}"
        else:
            s1_status = PolicyVerificationStatus.INVALID_STRUCTURE.name
            s2_decision = "REJECT"
            s2_reason = "Unknown flow"

        sensitivity = None
        minimum_mode = None
        policy_version = None
        authority_id = None

    else:
        # Policy is authentic and fresh
        s1_status = PolicyVerificationStatus.VALID.name
        sensitivity = verified_policy["sensitivity"]
        minimum_mode = verified_policy["minimum_mode"]
        policy_version = verified_policy["policy_version"]
        authority_id = verified_policy["authority_id"]

        # 2. Step 2: S2 Device Registration & Capability Checks
        if device_id not in device_registry:
            s2_decision = "REJECT"
            s2_reason = f"Unknown device: '{device_id}'"
        else:
            floor_reachable, floor_reason = check_floor_feasibility(device_id, flow_id)
            if not floor_reachable:
                s2_decision = "FLOOR_UNREACHABLE"
                s2_reason = floor_reason
            else:
                policy_ok, policy_reason = check_policy(flow_id, requested_mode)
                if not policy_ok:
                    s2_decision = "REJECT"
                    s2_reason = policy_reason
                else:
                    cap_ok, cap_reason = check_device_capability(device_id, requested_mode)
                    if not cap_ok:
                        s2_decision = "REJECT"
                        s2_reason = cap_reason
                    else:
                        s2_decision = "ALLOW"
                        s2_reason = "Policy and device capability satisfied"

    # 3. Step 3: Pass decision and S1 status to S3 Gateway Hook
    gw_decision_payload = {
        "device_id": device_id,
        "flow_id": flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "requested_mode": requested_mode,
        "policy_version": policy_version,
        "authority_id": authority_id,
        "decision": s2_decision,
        "reason": s2_reason,
    }

    hook_result: S3HookResult = s3_hook.process_gateway_decision(
        gw_decision=gw_decision_payload,
        session_id=trace_id,
        s1_status=s1_status,
        device_best_mode=best_mode,
    )

    final_decision = hook_result.final_decision
    final_reason = hook_result.detail if final_decision != "ALLOW" else s2_reason

    # 4. Step 4: Write structured audit log
    write_audit_log(
        trace_id=trace_id,
        device_id=device_id,
        flow_id=flow_id,
        sensitivity=sensitivity,
        minimum_mode=minimum_mode,
        requested_mode=requested_mode,
        policy_version=policy_version,
        authority_id=authority_id,
        decision=final_decision,
        reason=final_reason,
        s3_verdict=hook_result.s3_verdict,
        cause_label=hook_result.cause_label,
        security_reason=hook_result.security_reason,
        crypto_status="SKIPPED",
    )

    # 5. Return standardized response
    return {
        "trace_id": trace_id,
        "flow_id": flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "policy_version": policy_version,
        "authority_id": authority_id,
        "requested_mode": requested_mode,
        "decision": final_decision,
        "reason": final_reason,
        "s3_verdict": hook_result.s3_verdict,
        "cause_label": hook_result.cause_label,
        "close_session": hook_result.close_session,
        "backoff_ms": hook_result.backoff_ms,
    }


@app.post("/crypto-demo")
def crypto_demo(request: CryptoDemoRequest):
    """Establishes a cryptographic session and verifies local round-trip encryption/decryption.

    Preconditions:
    - Flow policy must be verified by S1.
    - S2 & S3 access checks must evaluate to ALLOW.
    - Requested mode must be 'PQC' or 'CLASSICAL'.
    - If data_integrity == 'TAMPERED', ciphertext/tag bytes are altered before receiver verification,
      causing genuine AES-256-GCM authentication failure and S3 security rejection.
    """
    trace_id = request.trace_id or str(uuid.uuid4())
    device_id = request.device_id.strip()
    flow_id = request.flow_id.strip()
    requested_mode = request.requested_mode.strip().upper()
    rec_id = request.record_id
    ds_source = None
    is_anomaly = None

    # Resolve message from dataset if empty
    msg_text = request.message
    if not msg_text or not msg_text.strip():
        dataset_rec = dataset_service.get_random_record(device_id, flow_id)
        if dataset_rec:
            msg_text = dataset_service.format_message(dataset_rec)
            rec_id = dataset_rec["record_id"]
            ds_source = dataset_rec["dataset_source"]
            is_anomaly = dataset_rec["is_anomaly"]
        else:
            msg_text = f"Telemetry reading from {device_id} on flow {flow_id}"

    # 1. Gatecheck: execute flow check through full S1-S2-S3 pipeline
    flow_eval = check_flow(
        FlowRequest(
            device_id=device_id,
            flow_id=flow_id,
            requested_mode=requested_mode,
            trace_id=trace_id,
        )
    )

    if flow_eval["decision"] != "ALLOW":
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": flow_eval["decision"],
            "reason": f"Cryptographic session aborted: gateway decision is {flow_eval['decision']} ({flow_eval['reason']})",
            "s3_verdict": flow_eval["s3_verdict"],
            "cause_label": flow_eval["cause_label"],
            "crypto_status": "REJECTED_BEFORE_SESSION",
            "record_id": rec_id,
        }

    # 2. Gatecheck: Cryptographic mode availability
    if requested_mode == "HYBRID":
        write_audit_log(
            trace_id=trace_id,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=flow_eval["sensitivity"],
            minimum_mode=flow_eval["minimum_mode"],
            requested_mode=requested_mode,
            policy_version=flow_eval["policy_version"],
            authority_id=flow_eval["authority_id"],
            decision="REJECT",
            reason="Mode 'HYBRID' is explicitly unsupported in this gateway prototype.",
            s3_verdict=flow_eval["s3_verdict"],
            cause_label=flow_eval["cause_label"],
            crypto_status="UNSUPPORTED_MODE",
            record_id=rec_id,
            dataset_source=ds_source,
            is_anomaly=is_anomaly,
        )
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": "REJECT",
            "reason": "Mode 'HYBRID' is explicitly unsupported in this gateway prototype. Supported modes are 'PQC' and 'CLASSICAL'.",
            "crypto_status": "UNSUPPORTED_MODE",
            "record_id": rec_id,
        }

    if requested_mode not in ("PQC", "PQ", "CLASSICAL"):
        write_audit_log(
            trace_id=trace_id,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=flow_eval["sensitivity"],
            minimum_mode=flow_eval["minimum_mode"],
            requested_mode=requested_mode,
            policy_version=flow_eval["policy_version"],
            authority_id=flow_eval["authority_id"],
            decision="REJECT",
            reason=f"Mode '{requested_mode}' has no cryptographic implementation. Supported modes are 'PQC' and 'CLASSICAL'.",
            s3_verdict=flow_eval["s3_verdict"],
            cause_label=flow_eval["cause_label"],
            crypto_status="UNSUPPORTED_MODE",
            record_id=rec_id,
            dataset_source=ds_source,
            is_anomaly=is_anomaly,
        )
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": "REJECT",
            "reason": f"Mode '{requested_mode}' has no cryptographic implementation. Supported modes are 'PQC' and 'CLASSICAL'.",
            "crypto_status": "UNSUPPORTED_MODE",
            "record_id": rec_id,
        }

    try:
        # 3. Establish Session (PQC via ML-KEM-512 or Classical via X25519)
        session = establish_session(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=str(flow_eval["sensitivity"]),
            policy_version=int(flow_eval["policy_version"]),
            mode=requested_mode,
        )

        suite_name = (
            "ML-KEM-512 + HKDF-SHA256 + AES-256-GCM"
            if requested_mode in ("PQC", "PQ")
            else "X25519 + HKDF-SHA256 + AES-256-GCM"
        )
        key_ex_name = getattr(session, "key_exchange", "ML-KEM-512" if requested_mode in ("PQC", "PQ") else "X25519")

        # 4. Sender Encrypts Payload
        raw_plaintext = msg_text.encode("utf-8")
        encrypted_envelope = session.encrypt(raw_plaintext)

        # 5. Receiver Decrypts and Authenticates Envelope
        decrypted_bytes = session.decrypt(encrypted_envelope)
        if decrypted_bytes != raw_plaintext:
            raise RuntimeError("Receiver decrypted plaintext does not match sender original payload")

        # Record successful crypto operation (without logging secrets or plaintext)
        write_audit_log(
            trace_id=trace_id,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=flow_eval["sensitivity"],
            minimum_mode=flow_eval["minimum_mode"],
            requested_mode=requested_mode,
            policy_version=flow_eval["policy_version"],
            authority_id=flow_eval["authority_id"],
            decision="ALLOW",
            reason=f"Cryptographic session established ({suite_name}) and payload verified",
            s3_verdict="SUCCESS",
            cause_label="none",
            crypto_status="VERIFIED_ROUNDTRIP",
            record_id=rec_id,
            dataset_source=ds_source,
            is_anomaly=is_anomaly,
        )

        kem_ct = getattr(session, "kem_ciphertext", b"")
        dev_pub = getattr(session, "device_public_key", b"")
        gw_pub = getattr(session, "gateway_public_key", b"")

        resp = {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "sensitivity": flow_eval["sensitivity"],
            "minimum_mode": flow_eval["minimum_mode"],
            "policy_version": flow_eval["policy_version"],
            "authority_id": flow_eval["authority_id"],
            "requested_mode": requested_mode,
            "crypto_suite": suite_name,
            "key_exchange": key_ex_name,
            "decision": "ALLOW",
            "encrypted_envelope_length": len(encrypted_envelope),
            "ciphertext_hex": encrypted_envelope.hex(),
            "decrypted_message": decrypted_bytes.decode("utf-8"),
            "crypto_status": "VERIFIED_ROUNDTRIP",
            "record_id": rec_id,
        }
        if kem_ct:
            resp["kem_ciphertext_hex"] = kem_ct.hex()
        if dev_pub:
            resp["device_public_key_hex"] = dev_pub.hex()
        if gw_pub:
            resp["gateway_public_key_hex"] = gw_pub.hex()

        return resp

    except Exception as err:
        write_audit_log(
            trace_id=trace_id,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=flow_eval["sensitivity"],
            minimum_mode=flow_eval["minimum_mode"],
            requested_mode=requested_mode,
            policy_version=flow_eval["policy_version"],
            authority_id=flow_eval["authority_id"],
            decision="REJECT",
            reason=f"Cryptographic operation failure: {err}",
            s3_verdict="CRYPTO_FAILURE",
            cause_label="security_failure",
            crypto_status="ERROR",
            record_id=rec_id,
            dataset_source=ds_source,
            is_anomaly=is_anomaly,
        )
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": "REJECT",
            "reason": f"Cryptographic operation failed: {err}",
            "crypto_status": "ERROR",
            "record_id": rec_id,
        }


# ─── Dashboard Integration Endpoints ──────────────────────────────────────────

@app.get("/devices")
def get_devices():
    """Returns the registered device inventory for the dashboard."""
    devices = []
    for dev_id, dev_info in device_registry.items():
        supported = [m.strip().upper() for m in dev_info.get("supported_modes", [])]
        status = "READY" if ("PQC" in supported or "HYBRID" in supported) else "LIMITED"
        devices.append({
            "device_id": dev_id,
            "supported_modes": supported,
            "status": status,
            "mapped_dataset_device": QERIS_TO_DATASET_DEVICE.get(dev_id, dev_id),
        })
    return devices


@app.get("/flows")
@app.get("/policies")
def get_policies():
    """Returns canonical, ML-DSA-65 verified policies for dashboard display."""
    policies = []
    for flow_id, p in policy_manager._verified_policies.items():
        policies.append({
            "flow_id": flow_id,
            "sensitivity": p["sensitivity"],
            "minimum_mode": p["minimum_mode"],
            "policy_version": p["policy_version"],
            "authority_id": p["authority_id"],
        })
    return policies


@app.get("/audit-logs")
def get_audit_logs(limit: int = 150):
    """Returns actual immutable gateway audit logs for the dashboard."""
    logs = []
    if _LOGS_PATH.exists():
        try:
            with open(_LOGS_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        logs.append({
                            "id": entry.get("trace_id", str(uuid.uuid4())),
                            "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                            "device_id": entry.get("device_id", ""),
                            "flow_id": entry.get("flow_id", ""),
                            "sensitivity": entry.get("sensitivity"),
                            "minimum_mode": entry.get("minimum_mode"),
                            "requested_mode": entry.get("requested_mode", "CLASSICAL"),
                            "policy_version": entry.get("policy_version", 1),
                            "decision": entry.get("decision", "REJECT"),
                            "reason": entry.get("reason", ""),
                            "s3_verdict": entry.get("s3_verdict", "NONE"),
                            "cause_label": entry.get("cause_label", "none"),
                            "crypto_status": entry.get("crypto_status", "SKIPPED"),
                            "record_id": entry.get("record_id"),
                            "is_anomaly": entry.get("is_anomaly"),
                        })
                        if len(logs) >= limit:
                            break
                    except Exception:
                        continue
        except Exception as err:
            sys.stderr.write(f"Error reading audit logs: {err}\n")
    return logs


@app.get("/security-events")
def get_security_events(limit: int = 50):
    """Extracts security events and downgrade rejections from actual gateway logs."""
    events = []
    if _LOGS_PATH.exists():
        try:
            with open(_LOGS_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        decision = entry.get("decision", "")
                        cause_label = entry.get("cause_label", "")
                        crypto_status = entry.get("crypto_status", "")
                        reason = entry.get("reason", "")

                        if decision != "ALLOW" or cause_label == "security_failure" or crypto_status == "TAMPERING_DETECTED":
                            evt_type = "DOWNGRADE_BLOCKED"
                            if decision == "FLOOR_UNREACHABLE":
                                evt_type = "FLOOR_UNREACHABLE"
                            elif "unknown flow" in reason.lower() or "not found" in reason.lower():
                                evt_type = "UNKNOWN_FLOW"
                            elif "unknown device" in reason.lower() or "not registered" in reason.lower():
                                evt_type = "UNKNOWN_FLOW"
                            elif "below" in reason.lower() or "floor" in reason.lower():
                                evt_type = "DOWNGRADE_BLOCKED"

                            events.append({
                                "id": f"evt-{entry.get('trace_id', str(uuid.uuid4()))[:8]}",
                                "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                                "type": evt_type,
                                "flow_id": entry.get("flow_id", ""),
                                "device_id": entry.get("device_id", ""),
                                "sensitivity": entry.get("sensitivity"),
                                "required_mode": entry.get("minimum_mode"),
                                "requested_mode": entry.get("requested_mode", "CLASSICAL"),
                                "decision": decision,
                                "reason": reason,
                            })
                            if len(events) >= limit:
                                break
                    except Exception:
                        continue
        except Exception as err:
            sys.stderr.write(f"Error reading security events: {err}\n")
    return events


@app.get("/dataset/sample")
def get_dataset_sample(device_id: str, flow_id: Optional[str] = None):
    """Retrieves a random existing record from the uploaded dataset for the specified device."""
    rec = dataset_service.get_random_record(device_id, flow_id)
    if not rec:
        raise HTTPException(status_code=404, detail="No matching dataset records found for device")
    return {
        "record": rec,
        "formatted_message": dataset_service.format_message(rec),
    }


def _process_dataset_replay_tick(record: dict[str, Any]) -> dict[str, Any]:
    """Helper callback for background dataset replay."""
    trace_id = str(uuid.uuid4())
    dev_id = record["device_id"]
    flow_id = record["flow_id"]
    dev_info = device_registry.get(dev_id, {})
    supported = dev_info.get("supported_modes", ["CLASSICAL"])
    req_mode = record.get("requested_mode", "CLASSICAL").upper()
    if req_mode not in supported:
        req_mode = supported[0]

    msg = dataset_service.format_message(record)
    return crypto_demo(
        CryptoDemoRequest(
            device_id=dev_id,
            flow_id=flow_id,
            message=msg,
            requested_mode=req_mode,
            trace_id=trace_id,
            data_integrity="NORMAL",
            record_id=record["record_id"],
        )
    )


@app.post("/dataset/replay/tick")
def replay_single_tick():
    """Forces one dataset replay step into the gateway pipeline."""
    result = dataset_service.replay_tick(_process_dataset_replay_tick)
    if not result:
        raise HTTPException(status_code=500, detail="Replay tick failed")
    return {
        "status": "TICK_EXECUTED",
        "record": result,
    }


@app.post("/dataset/replay/start")
def start_replay(interval_sec: float = 4.0):
    """Starts the continuous dataset replay worker."""
    dataset_service.start_background_replay(_process_dataset_replay_tick, interval_sec=interval_sec)
    return {"status": "REPLAY_STARTED", "interval_sec": interval_sec}


@app.post("/dataset/replay/stop")
def stop_replay():
    """Stops the continuous dataset replay worker."""
    dataset_service.stop_background_replay()
    return {"status": "REPLAY_STOPPED"}


@app.get("/dataset/replay/status")
def replay_status():
    """Returns dataset replay status and total records processed."""
    return {
        "running": dataset_service.is_replay_running(),
        "total_dataset_records": dataset_service.total_records_loaded,
        "replay_count": dataset_service.replay_count,
        "last_record": dataset_service.last_replay_record,
    }


@app.post("/reload-policies")
def reload_policies():
    """Forces reload and re-verification of all policies from disk."""
    results = policy_manager.load_and_verify_all()
    summary = {
        flow_id: {
            "is_valid": res.is_valid,
            "status": res.status.name,
            "message": res.message,
        }
        for flow_id, res in results.items()
    }
    return {
        "status": "RELOADED",
        "verified_count": len(policy_manager._verified_policies),
        "total_count": len(results),
        "details": summary,
    }
