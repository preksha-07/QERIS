"""
QERIS S2: Signed Policy Schema and Models

Defines the authoritative policy schema as specified in the Master Project Blueprint.
Enforces that:
1. Security floor is governed by approved_security_profiles (set of permitted profiles).
2. Flow is strictly bound to allowed device scopes.
3. Sensitivity is derived from the verified policy and CANNOT be overridden by devices.
4. Signatures cover canonical policy bytes with deterministic SHA-256 digest.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional

from pydantic import BaseModel, Field, field_validator

from qeris.s2.canonical_json import canonical_encode, compute_policy_digest
from qeris.s2.config import (
    DEFAULT_SIG_ALG,
    MODE_RANK,
    PROFILE_TO_MODE,
    SecurityMode,
    SensitivityTier,
)


class FlowPolicyModel(BaseModel):
    """Configuration for a specific data flow."""
    flow_id: str = Field(..., min_length=1, description="Unique flow identifier")
    device_scope: list[str] = Field(default_factory=lambda: ["*"], description="Allowed device IDs or ['*']")
    sensitivity: SensitivityTier = Field(..., description="Sensitivity tier (LOW, MEDIUM, HIGH, CRITICAL)")
    minimum_mode: SecurityMode = Field(..., description="Readable summary minimum mode floor")
    approved_security_profiles: list[str] = Field(..., min_length=1, description="Set of approved security profiles")

    @field_validator("approved_security_profiles")
    @classmethod
    def validate_profiles_against_minimum_mode(cls, profiles: list[str], info) -> list[str]:
        data = info.data
        minimum_mode = data.get("minimum_mode")
        if not minimum_mode:
            return profiles

        min_rank = MODE_RANK.get(str(minimum_mode), 0)
        # Verify that all approved profiles meet or exceed the minimum mode
        for p in profiles:
            p_mode = PROFILE_TO_MODE.get(p)
            if p_mode:
                p_rank = MODE_RANK.get(p_mode, 0)
                if p_rank < min_rank:
                    raise ValueError(
                        f"Approved profile '{p}' (mode {p_mode}) is below flow minimum mode '{minimum_mode}'"
                    )
        return profiles


class PolicyDocumentModel(BaseModel):
    """The authoritative policy content that is canonically signed."""
    authority_id: str = Field(..., min_length=1, description="Signing authority identity")
    policy_version: int = Field(..., ge=1, description="Monotonically increasing version integer >= 1")
    policies: dict[str, FlowPolicyModel] = Field(..., min_length=1, description="Map of flow_id to FlowPolicy")

    def canonical_dict(self) -> dict[str, Any]:
        """Returns standard dict representation suitable for canonical serialization."""
        return {
            "authority_id": self.authority_id,
            "policy_version": self.policy_version,
            "policies": {
                k: {
                    "flow_id": v.flow_id,
                    "device_scope": sorted(v.device_scope),
                    "sensitivity": v.sensitivity.value,
                    "minimum_mode": v.minimum_mode.value,
                    "approved_security_profiles": sorted(v.approved_security_profiles),
                }
                for k, v in sorted(self.policies.items())
            },
        }

    def canonical_bytes(self) -> bytes:
        return canonical_encode(self.canonical_dict())

    def compute_digest(self) -> str:
        return compute_policy_digest(self.canonical_dict())


class SignedPolicyEnvelopeModel(BaseModel):
    """Envelope distributing the policy, its digest, algorithm identifier, and signature."""
    policy: PolicyDocumentModel = Field(..., description="The policy document")
    policy_digest: str = Field(..., min_length=64, max_length=64, description="SHA-256 digest of canonical policy")
    sig_alg: str = Field(default=DEFAULT_SIG_ALG, description="Cryptographic signature algorithm")
    signature: str = Field(..., min_length=100, description="Hex-encoded signature bytes")

    def to_export_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.canonical_dict(),
            "policy_digest": self.policy_digest,
            "sig_alg": self.sig_alg,
            "signature": self.signature,
        }
