"""
QERIS S2: Gateway Session Manager and DEC-4 Policy Epoch Guard

Manages server-side gateway session contexts keyed by (device_id, flow_id).
Enforces DEC-4:
When policy updates, in-flight or active sessions are validated against the newly
active policy. If a session's negotiated profile or device scope is no longer permitted
under the new policy, the session is immediately invalidated (STALE) to prevent
stale authorization races.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from qeris.s2.crypto_engine import MessageEnvelope, create_context_aad
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel, SignedPolicyEnvelopeModel


class SessionState(str, Enum):
    INITIALIZING = "INITIALIZING"
    ACTIVE       = "ACTIVE"
    STALE        = "STALE"
    TERMINATED   = "TERMINATED"


@dataclass
class GatewaySessionContext:
    session_id: str
    device_id: str
    flow_id: str
    policy_version: int
    policy_digest: str
    policy_epoch: int
    sensitivity: str
    negotiated_profile: str
    negotiated_mode: str
    approved_profiles: list[str]
    session_key: bytes  # 32 bytes; strictly protected, NEVER logged
    created_at: float
    last_seen_at: float
    state: SessionState = SessionState.ACTIVE
    message_envelope: Optional[MessageEnvelope] = None

    def to_summary_dict(self) -> dict[str, Any]:
        """Safe summary for logging and APIs (omits secret keys)."""
        return {
            "session_id": self.session_id,
            "device_id": self.device_id,
            "flow_id": self.flow_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "policy_epoch": self.policy_epoch,
            "sensitivity": self.sensitivity,
            "negotiated_profile": self.negotiated_profile,
            "negotiated_mode": self.negotiated_mode,
            "state": self.state.value,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
        }


class SessionManager:
    """
    Thread-safe manager for gateway sessions and policy-epoch binding.
    """

    def __init__(self):
        # Keyed by (device_id, flow_id)
        self._sessions: dict[tuple[str, str], GatewaySessionContext] = {}
        # Keyed by session_id
        self._sessions_by_id: dict[str, GatewaySessionContext] = {}
        self._current_epoch: int = 1

    def advance_epoch(self) -> int:
        self._current_epoch += 1
        return self._current_epoch

    def get_current_epoch(self) -> int:
        return self._current_epoch

    def create_session(
        self,
        device_id: str,
        flow_id: str,
        policy_envelope: SignedPolicyEnvelopeModel,
        negotiated_profile: str,
        negotiated_mode: str,
        session_key: bytes,
    ) -> GatewaySessionContext:
        """
        Creates and stores a context-bound session for (device_id, flow_id).
        """
        now = time.time()
        session_id = str(uuid.uuid4())
        flow_policy = policy_envelope.policy.policies[flow_id]
        sensitivity = flow_policy.sensitivity.value

        context_aad = create_context_aad(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=sensitivity,
            policy_version=policy_envelope.policy.policy_version,
        )
        envelope = MessageEnvelope(session_key=session_key, context_aad=context_aad)

        ctx = GatewaySessionContext(
            session_id=session_id,
            device_id=device_id,
            flow_id=flow_id,
            policy_version=policy_envelope.policy.policy_version,
            policy_digest=policy_envelope.policy_digest,
            policy_epoch=self._current_epoch,
            sensitivity=sensitivity,
            negotiated_profile=negotiated_profile,
            negotiated_mode=negotiated_mode,
            approved_profiles=list(flow_policy.approved_security_profiles),
            session_key=session_key,
            created_at=now,
            last_seen_at=now,
            state=SessionState.ACTIVE,
            message_envelope=envelope,
        )

        flow_key = (device_id, flow_id)
        self._sessions[flow_key] = ctx
        self._sessions_by_id[session_id] = ctx
        return ctx

    def get_session(self, device_id: str, flow_id: str) -> Optional[GatewaySessionContext]:
        return self._sessions.get((device_id, flow_id))

    def get_session_by_id(self, session_id: str) -> Optional[GatewaySessionContext]:
        return self._sessions_by_id.get(session_id)

    def validate_and_rebind_session(
        self,
        session: GatewaySessionContext,
        active_policy_envelope: SignedPolicyEnvelopeModel,
    ) -> tuple[bool, str]:
        """
        Enforces DEC-4:
        Validates in-flight or active session against active policy.
        If the policy version/digest has changed:
        1. Checks if flow still exists.
        2. Checks if device is still in device_scope.
        3. Checks if session's negotiated_profile is still an approved profile for this flow.
        If all criteria hold: rebinds session to the new policy version and digest.
        If any criterion fails: marks session STALE, returns False.
        """
        active_version = active_policy_envelope.policy.policy_version
        active_digest = active_policy_envelope.policy_digest

        # If versions and digests match, context is fully fresh
        if session.policy_version == active_version and session.policy_digest == active_digest:
            session.last_seen_at = time.time()
            return True, "SESSION_VALID_CURRENT_EPOCH"

        # Policy update has occurred! Evaluate new policy rules for this session
        new_policies = active_policy_envelope.policy.policies
        if session.flow_id not in new_policies:
            session.state = SessionState.STALE
            return False, f"Flow '{session.flow_id}' removed in active policy version {active_version}"

        new_flow_policy = new_policies[session.flow_id]

        # Scope check
        if "*" not in new_flow_policy.device_scope and session.device_id not in new_flow_policy.device_scope:
            session.state = SessionState.STALE
            return False, f"Device '{session.device_id}' removed from scope for flow '{session.flow_id}'"

        # Approved profile check (Strict security floor preservation)
        if session.negotiated_profile not in new_flow_policy.approved_security_profiles:
            session.state = SessionState.STALE
            return False, (
                f"Session profile '{session.negotiated_profile}' is no longer approved under "
                f"new policy version {active_version} (approved: {new_flow_policy.approved_security_profiles})"
            )

        # Rebind session safely to the new policy epoch
        session.policy_version = active_version
        session.policy_digest = active_digest
        session.policy_epoch = self._current_epoch
        session.sensitivity = new_flow_policy.sensitivity.value
        session.approved_profiles = list(new_flow_policy.approved_security_profiles)
        session.last_seen_at = time.time()

        # Update AAD for subsequent message protections
        new_aad = create_context_aad(
            device_id=session.device_id,
            flow_id=session.flow_id,
            sensitivity=session.sensitivity,
            policy_version=active_version,
        )
        if session.message_envelope:
            session.message_envelope._context_aad = new_aad

        return True, f"SESSION_REBOUND_TO_POLICY_VERSION_{active_version}"

    def close_session(self, device_id: str, flow_id: str) -> None:
        ctx = self._sessions.pop((device_id, flow_id), None)
        if ctx:
            ctx.state = SessionState.TERMINATED
            self._sessions_by_id.pop(ctx.session_id, None)

    def clear(self) -> None:
        """Clears all session contexts for state reset."""
        self._sessions.clear()
        self._sessions_by_id.clear()

    def list_active_sessions(self) -> list[dict[str, Any]]:
        return [ctx.to_summary_dict() for ctx in self._sessions.values() if ctx.state == SessionState.ACTIVE]
