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
from policy_manager import S2PolicyManager
from qeris.policy.signed_policy import PolicyVerificationStatus
from s3_gateway_hook import S3GatewayHook, S3HookResult

app = FastAPI(
    title="QERIS Security Gateway",
    description="Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway",
    version="2.0.0",
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
    message: str
    requested_mode: str = "PQC"
    trace_id: Optional[str] = None


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
    """Establishes an S1 cryptographic session and verifies local round-trip encryption/decryption.

    Preconditions:
    - Flow policy must be verified by S1.
    - S2 & S3 access checks must evaluate to ALLOW.
    - Requested mode must be 'PQC'.
    """
    trace_id = request.trace_id or str(uuid.uuid4())
    device_id = request.device_id.strip()
    flow_id = request.flow_id.strip()
    requested_mode = request.requested_mode.strip().upper()

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
        }

    # 2. Gatecheck: Cryptographic mode availability
    if requested_mode not in ("PQC", "PQ"):
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
            reason="Cryptographic session establishment is only implemented for mode 'PQC'.",
            s3_verdict=flow_eval["s3_verdict"],
            cause_label=flow_eval["cause_label"],
            crypto_status="UNSUPPORTED_MODE",
        )
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": "REJECT",
            "reason": f"Mode '{requested_mode}' has no cryptographic implementation. Only post-quantum mode 'PQC' is supported.",
            "crypto_status": "UNSUPPORTED_MODE",
        }

    try:
        # 3. Establish ML-KEM-512 + HKDF-SHA256 + AES-256-GCM Session
        session: CryptoSession = establish_session(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=str(flow_eval["sensitivity"]),
            policy_version=int(flow_eval["policy_version"]),
            mode=requested_mode,
        )

        # 4. Sender Encrypts Payload
        raw_plaintext = request.message.encode("utf-8")
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
            reason="Cryptographic session established and payload verified",
            s3_verdict="SUCCESS",
            cause_label="none",
            crypto_status="VERIFIED_ROUNDTRIP",
        )

        kem_ct = session.kem_ciphertext

        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "sensitivity": flow_eval["sensitivity"],
            "minimum_mode": flow_eval["minimum_mode"],
            "policy_version": flow_eval["policy_version"],
            "authority_id": flow_eval["authority_id"],
            "crypto_suite": "ML-KEM-512 + HKDF-SHA256 + AES-256-GCM",
            "decision": "ALLOW",
            "encrypted_envelope_length": len(encrypted_envelope),
            "ciphertext_hex": encrypted_envelope.hex(),
            "kem_ciphertext_hex": kem_ct.hex() if kem_ct else None,
            "decrypted_message": decrypted_bytes.decode("utf-8"),
            "crypto_status": "VERIFIED_ROUNDTRIP",
        }

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
        )
        return {
            "trace_id": trace_id,
            "flow_id": flow_id,
            "decision": "REJECT",
            "reason": f"Cryptographic operation failed: {err}",
            "crypto_status": "ERROR",
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
