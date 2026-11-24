"""
QERIS S2: Unified Security Gateway Service

The core post-quantum IoT migration gateway implementing:
1. Canonical ML-DSA-65 signed policy verification and persistent anti-rollback storage.
2. Security floor and sensitivity enforcement (never trusts device-supplied sensitivity).
3. Gateway-registered capability registry checks and deterministic readiness classification.
4. Per-device token bucket rate limiting.
5. Session context management and DEC-4 policy-epoch integration.
6. S3 security state-machine and recovery integration hook.
7. Gateway-to-cloud forwarding with bounded outage handling.
8. Machine-readable structured audit logging.
"""
from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from qeris.s2.audit_logger import GatewayAuditLogger
from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.cloud_client import CloudForwardingClient, CloudForwardStatus
from qeris.s2.config import (
    BASELINE_DESCRIPTIONS,
    BASELINE_RECOVERY_PROPERTIES,
    DEFAULT_ALLOWED_SIG_ALGS,
    DEFAULT_AUTHORITY_ID,
    DEFAULT_SIG_ALG,
    MODE_RANK,
    PROFILE_TO_MODE,
    BaselineMode,
    GatewayConfig,
    SecurityMode,
    SensitivityTier,
)
from qeris.s2.crypto_engine import (
    MessageEnvelope,
    derive_session_key,
    load_authority_public_key,
)
from qeris.s2.policy_schema import (
    FlowPolicyModel,
    PolicyDocumentModel,
    SignedPolicyEnvelopeModel,
)
from qeris.s2.policy_store import PolicyStore
from qeris.s2.rate_limiter import DeviceRateLimiter
from qeris.s2.readiness import ReadinessStatus, evaluate_readiness
from qeris.s2.s3_adapter import S3IntegrationAdapter


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class CheckFlowRequest(BaseModel):
    device_id: str = Field(..., description="Device identifier")
    flow_id: str = Field(..., description="Requested flow identifier")
    requested_mode: str = Field(default="CLASSICAL", description="Security mode requested by device")
    requested_profile: Optional[str] = Field(default=None, description="Specific security profile requested")
    device_reported_sensitivity: Optional[str] = Field(
        default=None,
        description="Untrusted device-claimed sensitivity (strictly ignored for authorization)",
    )
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")
    scenario: Optional[str] = Field(default=None, description="Benchmark scenario identifier")


class HandshakeInitiateRequest(BaseModel):
    device_id: str
    flow_id: str
    client_public_key: Optional[str] = None
    offered_modes: list[str] = Field(default_factory=lambda: ["CLASSICAL"])
    offered_profiles: list[str] = Field(default_factory=list)
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")
    scenario: Optional[str] = Field(default=None, description="Benchmark scenario identifier")


class HandshakeCompleteRequest(BaseModel):
    device_id: str
    flow_id: str
    negotiated_profile: str
    session_key_hex: Optional[str] = None  # In real flow derived via KEM; optional for demo
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")


class TelemetrySubmitRequest(BaseModel):
    device_id: str
    flow_id: str
    session_id: Optional[str] = None
    payload: Any
    encrypted_envelope_hex: Optional[str] = None
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")


class RegisterDeviceRequest(BaseModel):
    device_id: str
    device_class: str = "esp32_constrained"
    supported_modes: list[str] = Field(default_factory=lambda: ["CLASSICAL", "HYBRID", "PQC"])
    supported_security_profiles: list[str] = Field(default_factory=list)
    memory_class: str = "LOW_RAM_320KB"
    ram_bytes_available: int = 320 * 1024
    max_packet_size_mtu: int = 1280
    firmware_version: str = "v1.0.0"


class QuarantineRequest(BaseModel):
    quarantined: bool
    reason: Optional[str] = None


class BaselineUpdateRequest(BaseModel):
    baseline_mode: BaselineMode
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")
    scenario: Optional[str] = Field(default=None, description="Benchmark scenario identifier")


class ResetRequest(BaseModel):
    reset_rate_limits: bool = Field(default=True, description="Reset token bucket rate limits")
    clear_sessions: bool = Field(default=True, description="Clear active session contexts")
    reset_cloud_queue: bool = Field(default=True, description="Reset cloud forwarding outage queue")
    reset_baseline: Optional[BaselineMode] = Field(
        default=BaselineMode.FULL_GATEWAY,
        description="Reset baseline to specified mode",
    )
    run_id: Optional[str] = Field(default=None, description="Experiment run identifier")


class ConfigUpdateRequest(BaseModel):
    baseline_mode: Optional[BaselineMode] = None
    rate_limit_capacity: Optional[float] = None
    rate_limit_refill_rate: Optional[float] = None
    rate_limit_enabled: Optional[bool] = None
    cloud_queue_max_size: Optional[int] = None


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def create_gateway_app(
    policy_store: Optional[PolicyStore] = None,
    registry: Optional[DeviceRegistry] = None,
    rate_limiter: Optional[DeviceRateLimiter] = None,
    cloud_client: Optional[CloudForwardingClient] = None,
    audit_logger: Optional[GatewayAuditLogger] = None,
    s3_adapter: Optional[S3IntegrationAdapter] = None,
    trusted_authorities: Optional[dict[str, Any]] = None,
    baseline_mode: BaselineMode = BaselineMode.FULL_GATEWAY,
    config: Optional[GatewayConfig] = None,
) -> FastAPI:
    """
    Creates and configures the unified QERIS Gateway FastAPI application.
    """
    app = FastAPI(
        title="QERIS Security Gateway",
        version="2.0.0",
        description="Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for IoT Edge-Cloud Systems.",
    )

    # Enable CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Configuration and Baseline Freeze
    app_config = config or GatewayConfig(baseline_mode=baseline_mode)
    app.state.config = app_config
    app.state.baseline_mode = app_config.baseline_mode

    # Administrative Authentication Middleware (Fail-Secure)
    @app.middleware("http")
    async def admin_auth_middleware(request: Request, call_next):
        if request.url.path.startswith("/api/v1/admin"):
            expected_key = getattr(app.state.config, "admin_api_key", None)
            if not expected_key:
                return Response(
                    content='{"detail": "Forbidden: Admin API access is disabled because no admin API key is configured"}',
                    status_code=403,
                    media_type="application/json",
                )
            admin_hdr = request.headers.get("X-Admin-Key")
            auth_hdr = request.headers.get("Authorization")
            is_authorized = (
                admin_hdr == expected_key or
                auth_hdr == f"Bearer {expected_key}" or
                auth_hdr == expected_key
            )
            if not is_authorized:
                return Response(
                    content='{"detail": "Unauthorized: Invalid or missing admin API key"}',
                    status_code=401,
                    media_type="application/json",
                )
        return await call_next(request)

    # Trusted authority keys mapping: authority_id -> public key material
    _trusted_authorities: dict[str, Any] = dict(trusted_authorities or {})

    # Initialize components with default or injected instances
    _policy_store = policy_store or PolicyStore()
    _registry = registry or DeviceRegistry()
    _rate_limiter = rate_limiter or DeviceRateLimiter(
        capacity=app_config.rate_limit_capacity,
        refill_rate=app_config.rate_limit_refill_rate,
    )
    from qeris.s2.config import DEFAULT_CLOUD_URL, DEFAULT_CLOUD_CA_CERT
    _cloud_client = cloud_client or CloudForwardingClient(
        cloud_url=getattr(app_config, "cloud_url", DEFAULT_CLOUD_URL),
        ca_cert_path=getattr(app_config, "cloud_ca_cert", DEFAULT_CLOUD_CA_CERT),
        max_queue_size=app_config.cloud_queue_max_size,
        timeout_seconds=app_config.cloud_forward_timeout_s,
    )
    _audit_logger = audit_logger or GatewayAuditLogger()
    _s3_adapter = s3_adapter or S3IntegrationAdapter(trusted_authorities=_trusted_authorities)

    # Session Manager
    from qeris.s2.session_manager import SessionManager
    _session_mgr = SessionManager()

    # Gateway Operational State
    app.state.policy_store = _policy_store
    app.state.registry = _registry
    app.state.rate_limiter = _rate_limiter
    app.state.cloud_client = _cloud_client
    app.state.audit_logger = _audit_logger
    app.state.s3_adapter = _s3_adapter
    app.state.session_mgr = _session_mgr
    app.state.trusted_authorities = _trusted_authorities

    # -----------------------------------------------------------------------
    # Core Flow Checking Logic (Blueprint §6, §10, §15)
    # -----------------------------------------------------------------------

    def execute_flow_check(
        device_id: str,
        flow_id: str,
        requested_mode: str,
        requested_profile: Optional[str] = None,
        untrusted_device_sensitivity: Optional[str] = None,
        run_id: Optional[str] = None,
        scenario: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Deterministic, security-floor-bounded flow evaluation pipeline.
        """
        current_baseline = app.state.baseline_mode
        rec_props = BASELINE_RECOVERY_PROPERTIES.get(current_baseline.value, {})
        adaptive_recovery = rec_props.get("adaptive_recovery", True)

        # Audit untrusted device claim if present
        if untrusted_device_sensitivity:
            _audit_logger.log_event(
                "device_claim_ignored",
                device_id=device_id,
                flow_id=flow_id,
                decision="AUDIT",
                reason=f"Device provided sensitivity '{untrusted_device_sensitivity}' was ignored; policy is authoritative",
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
            )

        # 1. Per-device rate limiting (if enabled in frozen config)
        if getattr(app.state.config, "rate_limit_enabled", True):
            allowed, remaining_tokens, retry_after = _rate_limiter.check_rate_limit(device_id)
            if not allowed:
                _audit_logger.log_event(
                    "rate_limit_exceeded",
                    device_id=device_id,
                    flow_id=flow_id,
                    decision="RATE_LIMITED",
                    reason=f"Device exceeded rate limit bucket (retry after {retry_after:.2f}s)",
                    rate_limited=True,
                    baseline_mode=current_baseline.value,
                    run_id=run_id,
                    scenario=scenario,
                    floor_violation=False,
                )
                return {
                    "decision": "REJECT",
                    "reason": "Per-device rate limit exceeded",
                    "status_code": 429,
                    "retry_after": retry_after,
                    "baseline_mode": current_baseline.value,
                    "run_id": run_id,
                    "scenario": scenario,
                }

        # 2. Retrieve verified active policy
        active_envelope = _policy_store.get_active_policy()
        if not active_envelope:
            _audit_logger.log_event(
                "policy_rejected",
                device_id=device_id,
                flow_id=flow_id,
                decision="REJECT",
                reason="No active verified policy installed on gateway",
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
            )
            return {
                "decision": "REJECT",
                "reason": "No active policy available on gateway",
                "status_code": 503,
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
            }

        policies = active_envelope.policy.policies
        if flow_id not in policies:
            _audit_logger.log_event(
                "policy_rejected",
                device_id=device_id,
                flow_id=flow_id,
                decision="REJECT",
                reason=f"Unknown flow '{flow_id}' not defined in active policy",
                policy_version=active_envelope.policy.policy_version,
                policy_digest=active_envelope.policy_digest,
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
            )
            return {
                "decision": "REJECT",
                "reason": f"Unknown flow '{flow_id}'",
                "status_code": 404,
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
            }

        flow_policy = policies[flow_id]
        sensitivity = flow_policy.sensitivity.value
        minimum_mode = flow_policy.minimum_mode.value
        approved_profiles = flow_policy.approved_security_profiles
        policy_version = active_envelope.policy.policy_version
        policy_digest = active_envelope.policy_digest
        authority_id = active_envelope.policy.authority_id

        # 3. Lookup Device in Capability Registry
        device_profile = _registry.get_device(device_id)
        if not device_profile:
            _audit_logger.log_event(
                "policy_rejected",
                device_id=device_id,
                flow_id=flow_id,
                decision="REJECT",
                reason=f"Device '{device_id}' is not enrolled in gateway capability registry",
                sensitivity=sensitivity,
                policy_version=policy_version,
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
            )
            return {
                "decision": "REJECT",
                "reason": f"Unknown device '{device_id}'",
                "sensitivity": sensitivity,
                "minimum_mode": minimum_mode,
                "policy_version": policy_version,
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
                "status_code": 403,
            }

        # 4. Deterministic Readiness Check
        readiness = evaluate_readiness(device_profile, flow_policy)
        if readiness.status == ReadinessStatus.NOT_READY:
            reasons_summary = "; ".join(readiness.reasons)
            _audit_logger.log_event(
                "readiness_rejected",
                device_id=device_id,
                flow_id=flow_id,
                decision="REJECT",
                reason=f"Device readiness evaluated to NOT_READY: {reasons_summary}",
                sensitivity=sensitivity,
                policy_version=policy_version,
                readiness_status=readiness.status.value,
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
            )
            return {
                "decision": "REJECT",
                "reason": f"Device readiness NOT_READY: {reasons_summary}",
                "sensitivity": sensitivity,
                "minimum_mode": minimum_mode,
                "policy_version": policy_version,
                "readiness": readiness.to_dict(),
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
                "status_code": 403,
            }

        # 5. Security Mode and Floor Feasibility Check
        norm_requested_mode = requested_mode.upper()
        if norm_requested_mode == "PQ":
            norm_requested_mode = "PQC"

        req_rank = MODE_RANK.get(norm_requested_mode, 0)
        floor_rank = MODE_RANK.get(minimum_mode, 0)
        floor_violated = False

        # Baseline Strategy Execution (S4 Baselines B1-B7)
        if current_baseline == BaselineMode.DOWNGRADE_ON_FAILURE:
            # Experimental baseline: deliberately permits downgrade below floor for research comparison
            is_floor_satisfied = True
            floor_violated = req_rank < floor_rank
            rejection_reason = ""
        elif current_baseline == BaselineMode.STATIC_CLASSICAL:
            # Static Classical baseline: only Classical allowed; cannot meet higher floors
            if norm_requested_mode != "CLASSICAL":
                is_floor_satisfied = False
                rejection_reason = "Static Classical baseline rejects non-classical requested mode"
            else:
                is_floor_satisfied = req_rank >= floor_rank
                rejection_reason = (
                    f"Requested mode '{requested_mode}' (rank {req_rank}) is below signed security floor "
                    f"'{minimum_mode}' (rank {floor_rank})"
                )
        elif current_baseline == BaselineMode.STATIC_HYBRID:
            # Static Hybrid baseline: only Hybrid allowed; cannot meet PQC floor
            if norm_requested_mode != "HYBRID":
                is_floor_satisfied = False
                rejection_reason = "Static Hybrid baseline rejects non-hybrid requested mode"
            else:
                is_floor_satisfied = req_rank >= floor_rank
                rejection_reason = (
                    f"Requested mode '{requested_mode}' (rank {req_rank}) is below signed security floor "
                    f"'{minimum_mode}' (rank {floor_rank})"
                )
        elif current_baseline == BaselineMode.STATIC_PQC:
            # Static PQC baseline: only PQC allowed
            if norm_requested_mode != "PQC":
                is_floor_satisfied = False
                rejection_reason = "Static PQC baseline rejects non-PQC requested mode"
            else:
                is_floor_satisfied = req_rank >= floor_rank
                rejection_reason = (
                    f"Requested mode '{requested_mode}' (rank {req_rank}) is below signed security floor "
                    f"'{minimum_mode}' (rank {floor_rank})"
                )
        else:
            # FULL_GATEWAY, SENSITIVITY_ONLY, STATIC_RETRY
            is_floor_satisfied = req_rank >= floor_rank
            rejection_reason = (
                f"Requested mode '{requested_mode}' (rank {req_rank}) is below signed security floor "
                f"'{minimum_mode}' (rank {floor_rank})"
            )

        # Specific profile check if requested
        if requested_profile:
            if requested_profile not in approved_profiles:
                is_floor_satisfied = False
                rejection_reason = f"Requested profile '{requested_profile}' not in approved set"

        if not is_floor_satisfied:
            # Consult S3 Hook for classified recovery / audit
            s3_res = _s3_adapter.process_decision(
                device_id=device_id,
                flow_id=flow_id,
                sensitivity=sensitivity,
                minimum_mode=minimum_mode,
                requested_mode=norm_requested_mode,
                policy_version=policy_version,
                initial_decision="REJECT",
                reason=rejection_reason,
                authority_id=authority_id,
                device_best_mode=device_profile.supported_modes[-1] if device_profile.supported_modes else None,
            )
            _audit_logger.log_event(
                "downgrade_blocked",
                device_id=device_id,
                flow_id=flow_id,
                decision=s3_res["final_decision"],
                reason=rejection_reason,
                sensitivity=sensitivity,
                mode=norm_requested_mode,
                policy_version=policy_version,
                policy_digest=policy_digest,
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
                floor_violation=False,
                details=s3_res,
            )
            return {
                "decision": s3_res["final_decision"],
                "reason": rejection_reason,
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
                "sensitivity": sensitivity,
                "minimum_mode": minimum_mode,
                "policy_version": policy_version,
                "policy_digest": policy_digest,
                "adaptive_recovery": adaptive_recovery,
                "floor_violation": False,
                "s3_verdict": s3_res["s3_verdict"],
                "status_code": 403,
            }

        # 6. Success: Security Floor Satisfied -> Consult S3 Hook for confirmation
        selected_profile = requested_profile or readiness.recommended_profile

        # In experimental DOWNGRADE_ON_FAILURE baseline, S3 enforcement is bypassed
        # to simulate naive unmanaged fallback devices for research comparison
        if current_baseline == BaselineMode.DOWNGRADE_ON_FAILURE:
            _audit_logger.log_event(
                "downgrade_permitted_experimental",
                device_id=device_id,
                flow_id=flow_id,
                decision="ALLOW",
                reason="Experimental baseline: downgrade_on_failure permitted",
                sensitivity=sensitivity,
                security_profile=selected_profile,
                mode=norm_requested_mode,
                policy_version=policy_version,
                policy_digest=policy_digest,
                baseline_mode=current_baseline.value,
                run_id=run_id,
                scenario=scenario,
                floor_violation=floor_violated,
                details={"baseline": "downgrade_on_failure", "floor_violation": floor_violated},
            )
            return {
                "decision": "ALLOW",
                "reason": "Experimental baseline: downgrade_on_failure permitted",
                "baseline_mode": current_baseline.value,
                "run_id": run_id,
                "scenario": scenario,
                "device_id": device_id,
                "flow_id": flow_id,
                "sensitivity": sensitivity,
                "minimum_mode": minimum_mode,
                "approved_security_profiles": approved_profiles,
                "selected_security_profile": selected_profile,
                "policy_version": policy_version,
                "policy_digest": policy_digest,
                "authority_id": authority_id,
                "readiness": readiness.to_dict(),
                "adaptive_recovery": False,
                "floor_violation": floor_violated,
                "s3_verdict": "BYPASSED_FOR_BASELINE",
                "status_code": 200,
            }

        readiness_dict = readiness.to_dict()
        # For non-adaptive baselines (B1-B4, B6), suppress adaptive recovery hints
        if not adaptive_recovery:
            readiness_dict["requires_fragmentation"] = False
            readiness_dict["adaptive_recovery"] = False

        s3_res = _s3_adapter.process_decision(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=sensitivity,
            minimum_mode=minimum_mode,
            requested_mode=norm_requested_mode,
            policy_version=policy_version,
            initial_decision="ALLOW",
            reason="Policy and readiness criteria satisfied",
            authority_id=authority_id,
            device_best_mode=device_profile.supported_modes[-1] if device_profile.supported_modes else None,
        )

        if not adaptive_recovery:
            s3_res["backoff_ms"] = 0

        final_decision = s3_res["final_decision"]
        _audit_logger.log_event(
            "handshake_verified" if final_decision == "ALLOW" else "security_rejected",
            device_id=device_id,
            flow_id=flow_id,
            decision=final_decision,
            reason=s3_res["detail"],
            sensitivity=sensitivity,
            security_profile=selected_profile,
            mode=norm_requested_mode,
            policy_version=policy_version,
            policy_digest=policy_digest,
            readiness_status=readiness.status.value,
            baseline_mode=current_baseline.value,
            run_id=run_id,
            scenario=scenario,
            floor_violation=False,
            details=s3_res,
        )

        return {
            "decision": final_decision,
            "reason": s3_res["detail"],
            "baseline_mode": current_baseline.value,
            "run_id": run_id,
            "scenario": scenario,
            "device_id": device_id,
            "flow_id": flow_id,
            "sensitivity": sensitivity,
            "minimum_mode": minimum_mode,
            "approved_security_profiles": approved_profiles,
            "selected_security_profile": selected_profile,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "authority_id": authority_id,
            "readiness": readiness_dict,
            "adaptive_recovery": adaptive_recovery,
            "floor_violation": False,
            "s3_verdict": s3_res["s3_verdict"],
            "status_code": 200 if final_decision == "ALLOW" else 403,
        }

    # -----------------------------------------------------------------------
    # Endpoints
    # -----------------------------------------------------------------------

    @app.post("/check-flow")
    def check_flow(req: CheckFlowRequest, response: Response):
        """
        Backward-compatible and UI integration endpoint.
        """
        res = execute_flow_check(
            device_id=req.device_id,
            flow_id=req.flow_id,
            requested_mode=req.requested_mode,
            requested_profile=req.requested_profile,
            untrusted_device_sensitivity=req.device_reported_sensitivity,
            run_id=req.run_id,
            scenario=req.scenario,
        )
        response.status_code = res.pop("status_code", 200)
        return res

    @app.post("/api/v1/handshake/initiate")
    def initiate_handshake(req: HandshakeInitiateRequest, response: Response):
        """
        Initiates a secure handshake by validating device, policy, and readiness.
        """
        requested_mode = req.offered_modes[0] if req.offered_modes else "CLASSICAL"
        requested_profile = req.offered_profiles[0] if req.offered_profiles else None
        res = execute_flow_check(
            device_id=req.device_id,
            flow_id=req.flow_id,
            requested_mode=requested_mode,
            requested_profile=requested_profile,
            run_id=req.run_id,
            scenario=req.scenario,
        )
        response.status_code = res.pop("status_code", 200)
        return res

    @app.post("/api/v1/handshake/complete")
    def complete_handshake(req: HandshakeCompleteRequest):
        """
        Completes session establishment and binds session context to policy epoch.
        """
        active_envelope = _policy_store.get_active_policy()
        if not active_envelope:
            raise HTTPException(status_code=503, detail="No active policy installed")

        if req.flow_id not in active_envelope.policy.policies:
            raise HTTPException(status_code=404, detail="Flow not in active policy")

        flow_policy = active_envelope.policy.policies[req.flow_id]
        if req.negotiated_profile not in flow_policy.approved_security_profiles:
            raise HTTPException(status_code=403, detail="Negotiated profile is not in approved set")

        session_key = bytes.fromhex(req.session_key_hex) if req.session_key_hex else os.urandom(32)
        negotiated_mode = PROFILE_TO_MODE.get(req.negotiated_profile, "CLASSICAL")

        ctx = _session_mgr.create_session(
            device_id=req.device_id,
            flow_id=req.flow_id,
            policy_envelope=active_envelope,
            negotiated_profile=req.negotiated_profile,
            negotiated_mode=negotiated_mode,
            session_key=session_key,
        )

        _audit_logger.log_event(
            "handshake_complete",
            device_id=req.device_id,
            flow_id=req.flow_id,
            decision="ACTIVE",
            reason="Handshake established successfully",
            session_id=ctx.session_id,
            sensitivity=ctx.sensitivity,
            security_profile=ctx.negotiated_profile,
            policy_version=ctx.policy_version,
            policy_digest=ctx.policy_digest,
        )

        return {
            "status": "SESSION_ACTIVE",
            "session_id": ctx.session_id,
            "device_id": ctx.device_id,
            "flow_id": ctx.flow_id,
            "sensitivity": ctx.sensitivity,
            "negotiated_profile": ctx.negotiated_profile,
            "policy_version": ctx.policy_version,
            "policy_digest": ctx.policy_digest,
            "policy_epoch": ctx.policy_epoch,
        }

    @app.post("/api/v1/telemetry")
    def submit_telemetry(req: TelemetrySubmitRequest):
        """
        Receives encrypted/protected device telemetry, enforces DEC-4 epoch validity,
        unpacks/authenticates message, and forwards to the cloud pipeline.
        """
        # Look up active session
        session = _session_mgr.get_session(req.device_id, req.flow_id)
        if not session and req.session_id:
            session = _session_mgr.get_session_by_id(req.session_id)

        active_envelope = _policy_store.get_active_policy()
        if not active_envelope:
            raise HTTPException(status_code=503, detail="No active policy installed")

        # DEC-4 Check: Policy Epoch Validation
        if session:
            is_valid, msg = _session_mgr.validate_and_rebind_session(session, active_envelope)
            if not is_valid:
                _audit_logger.log_event(
                    "stale_epoch_rejected",
                    device_id=req.device_id,
                    flow_id=req.flow_id,
                    decision="REJECT",
                    reason=f"DEC-4 Guard rejected stale session: {msg}",
                    session_id=session.session_id,
                    policy_version=session.policy_version,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"DEC-4 Policy Epoch Mismatch: {msg}. Renegotiation required.",
                )
            sensitivity = session.sensitivity
            security_profile = session.negotiated_profile
        else:
            # Ephemeral flow validation if session-less submission
            flow_policy = active_envelope.policy.policies.get(req.flow_id)
            if not flow_policy:
                raise HTTPException(status_code=404, detail="Unknown flow")
            sensitivity = flow_policy.sensitivity.value
            security_profile = flow_policy.approved_security_profiles[0]

        event_id = str(uuid.uuid4())
        now = time.time()

        # Decrypt envelope if encrypted wire hex provided
        payload_content = req.payload
        if req.encrypted_envelope_hex and session and session.message_envelope:
            try:
                env_bytes = bytes.fromhex(req.encrypted_envelope_hex)
                decrypted_bytes = session.message_envelope.decrypt(env_bytes)
                import json
                try:
                    payload_content = json.loads(decrypted_bytes.decode("utf-8"))
                except Exception:
                    payload_content = decrypted_bytes.decode("utf-8")
            except Exception as exc:
                _audit_logger.log_event(
                    "telemetry_decryption_failed",
                    device_id=req.device_id,
                    flow_id=req.flow_id,
                    decision="REJECT",
                    reason=f"Envelope decryption or AEAD auth failed: {exc}",
                )
                raise HTTPException(status_code=400, detail=f"Message authentication failed: {exc}")

        # Prepare Cloud Forwarding Package
        cloud_payload = {
            "event_id": event_id,
            "device_id": req.device_id,
            "flow_id": req.flow_id,
            "timestamp": now,
            "sensitivity": sensitivity,
            "security_profile": security_profile,
            "policy_version": active_envelope.policy.policy_version,
            "policy_digest": active_envelope.policy_digest,
            "payload": payload_content,
            "gateway_decision": "ALLOW",
        }

        # Forward to Cloud with Bounded Outage Handling
        forward_res = _cloud_client.forward_telemetry(cloud_payload)

        _audit_logger.log_event(
            "data_sent",
            device_id=req.device_id,
            flow_id=req.flow_id,
            decision="ALLOW",
            reason="Telemetry accepted locally and forwarded/queued for cloud",
            sensitivity=sensitivity,
            security_profile=security_profile,
            policy_version=active_envelope.policy.policy_version,
            policy_digest=active_envelope.policy_digest,
            cloud_status=forward_res.status.value,
            baseline_mode=app.state.baseline_mode.value,
            run_id=req.run_id,
            details={"cloud_detail": forward_res.detail, "event_id": event_id},
        )

        return {
            "status": "ACCEPTED",
            "event_id": event_id,
            "device_id": req.device_id,
            "flow_id": req.flow_id,
            "sensitivity": sensitivity,
            "cloud_delivery": forward_res.status.value,
            "queue_size": forward_res.queue_size,
            "baseline_mode": app.state.baseline_mode.value,
            "run_id": req.run_id,
        }

    # -----------------------------------------------------------------------
    # Admin & Policy Management Endpoints (Blueprint §8, §9, §14)
    # -----------------------------------------------------------------------

    @app.post("/api/v1/admin/policy")
    def install_policy(envelope_dict: dict[str, Any], response: Response):
        """
        Installs a new ML-DSA-65 signed policy envelope into persistent anti-rollback storage.
        """
        res = _policy_store.install_policy(envelope_dict, _trusted_authorities)
        if not res.success:
            _audit_logger.log_event(
                "policy_installation_failed",
                device_id="ADMIN",
                flow_id="*",
                decision="REJECT",
                reason=res.message,
                policy_version=res.policy_version,
                policy_digest=res.policy_digest,
            )
            response.status_code = 400
            return {
                "success": False,
                "status": res.status,
                "message": res.message,
            }

        # Advance policy epoch in Session Manager upon successful installation
        new_epoch = _session_mgr.advance_epoch()

        _audit_logger.log_event(
            "policy_installed",
            device_id="ADMIN",
            flow_id="*",
            decision="INSTALLED",
            reason=res.message,
            policy_version=res.policy_version,
            policy_digest=res.policy_digest,
            details={"new_epoch": new_epoch},
        )

        return {
            "success": True,
            "status": res.status,
            "message": res.message,
            "authority_id": res.authority_id,
            "policy_version": res.policy_version,
            "policy_digest": res.policy_digest,
            "policy_epoch": new_epoch,
        }

    @app.get("/api/v1/admin/policy")
    def get_active_policy():
        active = _policy_store.get_active_policy()
        if not active:
            return {"active": False, "message": "No active policy installed"}
        return {
            "active": True,
            "authority_id": active.policy.authority_id,
            "policy_version": active.policy.policy_version,
            "policy_digest": active.policy_digest,
            "sig_alg": active.sig_alg,
            "flows": {k: v.model_dump() for k, v in active.policy.policies.items()},
            "current_epoch": _session_mgr.get_current_epoch(),
        }

    @app.get("/api/v1/admin/policy/history")
    def get_policy_history():
        return {
            "history": _policy_store.get_history(),
        }

    @app.post("/api/v1/admin/devices")
    def register_device(req: RegisterDeviceRequest):
        profile = DeviceCapabilityProfile(
            device_id=req.device_id,
            device_class=req.device_class,
            supported_modes=req.supported_modes,
            supported_security_profiles=req.supported_security_profiles or [
                "CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"
            ],
            memory_class=req.memory_class,
            ram_bytes_available=req.ram_bytes_available,
            max_packet_size_mtu=req.max_packet_size_mtu,
            firmware_version=req.firmware_version,
        )
        _registry.register_device(profile)
        _audit_logger.log_event(
            "device_registered",
            device_id=req.device_id,
            flow_id="*",
            decision="REGISTERED",
            reason=f"Device {req.device_id} registered with class {req.device_class}",
        )
        return {"status": "REGISTERED", "device_id": req.device_id}

    @app.get("/api/v1/admin/devices")
    def list_devices():
        devices = _registry.list_devices()
        return {"count": len(devices), "devices": [d.to_dict() for d in devices]}

    @app.get("/api/v1/admin/devices/{device_id}")
    def get_device(device_id: str):
        dev = _registry.get_device(device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")
        return dev.to_dict()

    @app.post("/api/v1/admin/devices/{device_id}/quarantine")
    def quarantine_device(device_id: str, req: QuarantineRequest):
        ok = _registry.set_quarantine(device_id, req.quarantined, req.reason)
        if not ok:
            raise HTTPException(status_code=404, detail="Device not found")
        _audit_logger.log_event(
            "device_quarantined" if req.quarantined else "device_unquarantined",
            device_id=device_id,
            flow_id="*",
            decision="QUARANTINED" if req.quarantined else "UNQUARANTINED",
            reason=req.reason or "Admin action",
        )
        return {"device_id": device_id, "quarantined": req.quarantined, "reason": req.reason}

    @app.get("/api/v1/admin/audit-logs")
    def get_audit_logs(limit: int = Query(100, ge=1, le=1000)):
        return {"logs": _audit_logger.read_logs(limit=limit)}

    @app.get("/api/v1/admin/baseline")
    def get_baseline_mode():
        mode = app.state.baseline_mode.value
        return {
            "status": "ONLINE",
            "baseline_mode": mode,
            "description": BASELINE_DESCRIPTIONS.get(mode, ""),
            "recovery_properties": BASELINE_RECOVERY_PROPERTIES.get(mode, {}),
            "frozen": True,
            "all_available_baselines": [m.value for m in BaselineMode],
        }

    @app.post("/api/v1/admin/baseline")
    def set_baseline_mode(req: BaselineUpdateRequest):
        app.state.baseline_mode = req.baseline_mode
        app.state.config.baseline_mode = req.baseline_mode
        _audit_logger.log_event(
            "baseline_mode_changed",
            device_id="gateway",
            flow_id="*",
            decision="UPDATED",
            reason=f"Baseline mode set to {req.baseline_mode.value}",
            baseline_mode=req.baseline_mode.value,
            run_id=req.run_id,
            scenario=req.scenario,
        )
        return {
            "status": "UPDATED",
            "baseline_mode": app.state.baseline_mode.value,
            "description": BASELINE_DESCRIPTIONS.get(req.baseline_mode.value, ""),
            "recovery_properties": BASELINE_RECOVERY_PROPERTIES.get(req.baseline_mode.value, {}),
            "frozen": True,
        }

    @app.get("/api/v1/admin/config")
    def get_config():
        cfg = app.state.config
        return {
            "config": cfg.to_dict(),
            "config_version": cfg.config_version,
            "config_digest": cfg.compute_digest(),
            "frozen": True,
        }

    @app.post("/api/v1/admin/config")
    def update_config(req: ConfigUpdateRequest):
        cfg = app.state.config
        if req.baseline_mode is not None:
            cfg.baseline_mode = req.baseline_mode
            app.state.baseline_mode = req.baseline_mode
        if req.rate_limit_capacity is not None:
            cfg.rate_limit_capacity = req.rate_limit_capacity
            _rate_limiter.capacity = req.rate_limit_capacity
        if req.rate_limit_refill_rate is not None:
            cfg.rate_limit_refill_rate = req.rate_limit_refill_rate
            _rate_limiter.refill_rate = req.rate_limit_refill_rate
        if req.rate_limit_enabled is not None:
            cfg.rate_limit_enabled = req.rate_limit_enabled
        if req.cloud_queue_max_size is not None:
            cfg.cloud_queue_max_size = req.cloud_queue_max_size
        _audit_logger.log_event(
            "config_updated",
            device_id="gateway",
            flow_id="*",
            decision="UPDATED",
            reason="Gateway configuration updated via admin API",
            baseline_mode=cfg.baseline_mode.value,
            details={"new_digest": cfg.compute_digest()},
        )
        return {
            "status": "CONFIG_UPDATED",
            "config": cfg.to_dict(),
            "config_digest": cfg.compute_digest(),
        }

    @app.post("/api/v1/admin/reset")
    def reset_state(req: ResetRequest):
        if getattr(req, "reset_rate_limits", True):
            _rate_limiter.clear()
        if getattr(req, "clear_sessions", True):
            _session_mgr.clear()
        if getattr(req, "reset_cloud_queue", True):
            _cloud_client.clear()
        if req.reset_baseline is not None:
            app.state.baseline_mode = req.reset_baseline
            app.state.config.baseline_mode = req.reset_baseline
        _audit_logger.log_event(
            "state_reset",
            device_id="gateway",
            flow_id="*",
            decision="RESET",
            reason="Gateway experiment state reset via admin API",
            baseline_mode=app.state.baseline_mode.value,
            run_id=req.run_id,
            details={
                "rate_limits_cleared": getattr(req, "reset_rate_limits", True),
                "sessions_cleared": getattr(req, "clear_sessions", True),
                "cloud_queue_cleared": getattr(req, "reset_cloud_queue", True),
                "effective_baseline": app.state.baseline_mode.value,
            },
        )
        return {
            "status": "RESET_COMPLETED",
            "baseline_mode": app.state.baseline_mode.value,
            "sessions_cleared": getattr(req, "clear_sessions", True),
            "rate_limits_cleared": getattr(req, "reset_rate_limits", True),
            "cloud_queue_cleared": getattr(req, "reset_cloud_queue", True),
            "config_digest": app.state.config.compute_digest(),
        }

    @app.get("/health")
    @app.get("/api/v1/gateway/health")
    def gateway_health():
        active = _policy_store.get_active_policy()
        return {
            "status": "UP",
            "service": "QERIS Security Gateway",
            "baseline_mode": app.state.baseline_mode.value,
            "policy_installed": active is not None,
        }

    @app.get("/api/v1/gateway/status")
    def gateway_status():
        active = _policy_store.get_active_policy()
        return {
            "status": "ONLINE",
            "service": "QERIS Security Gateway",
            "baseline_mode": app.state.baseline_mode.value,
            "config_version": app.state.config.config_version,
            "config_digest": app.state.config.compute_digest(),
            "policy_installed": active is not None,
            "active_policy_version": active.policy.policy_version if active else None,
            "active_policy_digest": active.policy_digest if active else None,
            "active_sessions_count": len(_session_mgr.list_active_sessions()),
            "cloud_queue_size": _cloud_client.queue_size,
            "cloud_dropped_count": _cloud_client.dropped_count,
        }

    return app
