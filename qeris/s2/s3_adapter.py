"""
QERIS S2: S3 Security State-Machine and Recovery Adapter

Integrates S2 Gateway with the S3 Security State Machine, Downgrade Rejector,
and Recovery Controller via S3GatewayHook.
Ensures that the S2 Gateway strictly obeys the state machine decisions:
S3 can tighten an S2 ALLOW to REJECT, but S3 NEVER relaxes a REJECT to ALLOW.
"""
from __future__ import annotations

import sys
import os
from typing import Any, Optional

# Ensure s3 is on path
_S3_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "s3"))
if _S3_PATH not in sys.path:
    sys.path.insert(0, _S3_PATH)

try:
    from s3_gateway_hook import S3GatewayHook, S3HookResult
    _S3_AVAILABLE = True
except ImportError:
    _S3_AVAILABLE = False
    S3GatewayHook = None
    S3HookResult = None


def classify_s1_exception(exc: Exception) -> str:
    """
    Maps S1/S2 exception types to S1 status strings for S3 taxonomy consumption.
    """
    name = type(exc).__name__
    msg = str(exc).lower()
    if name in ("AuthenticationError", "S1AuthenticationError") or "authentication" in msg or "tag" in msg or "signature" in msg:
        return "INVALID_SIGNATURE"
    if name in ("ReplayError", "S1ReplayError") or "replay" in msg or "stale" in msg:
        return "STALE_POLICY"
    if name in ("CryptoInputError", "ClassicalCryptoInputError", "MessageCryptoError", "PolicyValidationError") or "malformed" in msg:
        return "INVALID_STRUCTURE"
    if "timeout" in msg:
        return "TIMEOUT"
    return "INVALID_SIGNATURE"


class S3IntegrationAdapter:
    """
    Adapter interfacing S2 Gateway decisions with the S3 Security State Machine.
    """

    def __init__(
        self,
        audit_level: str = "standard",
        rate_limit_per_min: int = 120,
        trusted_authorities: Optional[Any] = None,
    ):
        if _S3_AVAILABLE and S3GatewayHook is not None:
            kwargs = {
                "audit_level": audit_level,
                "rate_limit_per_min": rate_limit_per_min,
            }
            if trusted_authorities is not None:
                trusted_set = (
                    frozenset(trusted_authorities.keys())
                    if hasattr(trusted_authorities, "keys")
                    else frozenset(trusted_authorities)
                )
                kwargs["trusted_authorities"] = trusted_set
            self._hook = S3GatewayHook(**kwargs)
        else:
            self._hook = None

    def process_decision(
        self,
        *,
        device_id: str,
        flow_id: str,
        sensitivity: Optional[str],
        minimum_mode: Optional[str],
        requested_mode: str,
        policy_version: Optional[int],
        initial_decision: str,  # "ALLOW", "REJECT", "FLOOR_UNREACHABLE"
        reason: str,
        authority_id: Optional[str] = None,
        device_best_mode: Optional[str] = None,
        s1_status: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Submits gateway decision to S3 hook and returns finalized outcome.
        """
        gw_dict = {
            "device_id": device_id,
            "flow_id": flow_id,
            "sensitivity": sensitivity,
            "minimum_mode": minimum_mode,
            "requested_mode": requested_mode,
            "policy_version": policy_version,
            "decision": initial_decision,
            "reason": reason,
            "authority_id": authority_id,
        }

        if self._hook is not None:
            hook_res = self._hook.process_gateway_decision(
                gw_dict,
                session_id=session_id,
                s1_status=s1_status,
                device_best_mode=device_best_mode,
            )
            return {
                "final_decision": hook_res.final_decision,
                "s3_verdict": hook_res.s3_verdict,
                "cause_label": hook_res.cause_label,
                "security_reason": hook_res.security_reason,
                "detail": hook_res.detail,
                "close_session": hook_res.close_session,
                "backoff_ms": hook_res.backoff_ms,
            }
        else:
            # Fallback if S3 hook is not directly loaded
            return {
                "final_decision": initial_decision,
                "s3_verdict": "PERMIT" if initial_decision == "ALLOW" else "BLOCK",
                "cause_label": "none" if initial_decision == "ALLOW" else "security_failure",
                "security_reason": None if initial_decision == "ALLOW" else reason,
                "detail": reason,
                "close_session": initial_decision != "ALLOW",
                "backoff_ms": 0,
            }
