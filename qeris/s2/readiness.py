"""
QERIS S2: Deterministic Readiness Classification

Implements pure, transparent, deterministic readiness classification rules as specified
in the Master Project Blueprint. Absolutely NO AI/ML prediction is used.

Categories:
- READY: Flow can activate normally with an approved security profile.
- PARTIALLY_READY: Flow is feasible, but operational constraints exist (e.g. fragmentation needed).
- NOT_READY: Flow cannot activate safely. MUST NOT trigger a security floor downgrade.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from qeris.s2.capability_registry import DeviceCapabilityProfile
from qeris.s2.config import (
    MODE_RANK,
    PROFILE_TO_MODE,
    SecurityProfile,
)
from qeris.s2.policy_schema import FlowPolicyModel

# Estimated Wire Sizes per Security Mode
WIRE_SIZE_MAP: dict[str, int] = {
    "CLASSICAL": 240,    # ClientHello + ServerHello + Finished
    "HYBRID":    2336,   # X25519MLKEM768: 1216 (client share) + 1120 (server share)
    "PQC":       1568,   # ML-KEM-512: 800 (pk) + 768 (ct)
}

# Profile Memory Requirements in Bytes
PROFILE_RAM_REQUIREMENTS: dict[str, int] = {
    SecurityProfile.CLASSICAL_ECDH_AESGCM.value:        8 * 1024,   # 8 KB
    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value:   32 * 1024,  # 32 KB
    SecurityProfile.PQC_MLKEM512_AESGCM.value:          48 * 1024,  # 48 KB
    SecurityProfile.PQC_MLKEM768_AESGCM.value:          64 * 1024,  # 64 KB
    SecurityProfile.PQC_MLKEM1024_AESGCM.value:         96 * 1024,  # 96 KB
}


class ReadinessStatus(str, Enum):
    READY           = "READY"
    PARTIALLY_READY = "PARTIALLY_READY"
    NOT_READY       = "NOT_READY"


@dataclass
class ReadinessResult:
    status: ReadinessStatus
    feasible_profiles: list[str]
    recommended_profile: Optional[str]
    reasons: list[str] = field(default_factory=list)
    requires_fragmentation: bool = False
    estimated_wire_size: int = 0
    available_ram_bytes: int = 0
    required_ram_bytes: int = 0

    @property
    def is_executable(self) -> bool:
        """Returns True if the session can activate (READY or PARTIALLY_READY)."""
        return self.status != ReadinessStatus.NOT_READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "feasible_profiles": self.feasible_profiles,
            "recommended_profile": self.recommended_profile,
            "reasons": self.reasons,
            "requires_fragmentation": self.requires_fragmentation,
            "estimated_wire_size": self.estimated_wire_size,
        }


def evaluate_readiness(
    device: DeviceCapabilityProfile,
    flow: FlowPolicyModel,
    *,
    max_consecutive_failures: int = 3,
    consecutive_security_failures_limit: int = 2,
) -> ReadinessResult:
    """
    Evaluates deterministic readiness rules for a (device, flow) pair.

    Rules:
    1. Device Quarantine: If device is quarantined -> NOT_READY.
    2. Device Scope: If device_id not in flow.device_scope (and '*' not present) -> NOT_READY.
    3. Profile Feasibility: Intersection of device supported profiles and flow approved profiles.
       If intersection is empty -> NOT_READY.
    4. Memory Verification: Checks if device has sufficient RAM for feasible profiles.
    5. Packet Size & MTU: Compares wire size to device MTU.
    6. Health History: Inspects recent results for consecutive failures.
    """
    reasons: list[str] = []

    # 1. Quarantine check
    if device.quarantined:
        return ReadinessResult(
            status=ReadinessStatus.NOT_READY,
            feasible_profiles=[],
            recommended_profile=None,
            reasons=[f"Device '{device.device_id}' is quarantined: {device.quarantine_reason or 'No reason provided'}"],
        )

    # 2. Device scope check
    if "*" not in flow.device_scope and device.device_id not in flow.device_scope:
        return ReadinessResult(
            status=ReadinessStatus.NOT_READY,
            feasible_profiles=[],
            recommended_profile=None,
            reasons=[f"Device '{device.device_id}' is not in policy device scope: {flow.device_scope}"],
        )

    # 3. Profile intersection
    supported_set = set(device.supported_security_profiles)
    approved_set = set(flow.approved_security_profiles)
    candidate_profiles = [p for p in flow.approved_security_profiles if p in supported_set]

    if not candidate_profiles:
        return ReadinessResult(
            status=ReadinessStatus.NOT_READY,
            feasible_profiles=[],
            recommended_profile=None,
            reasons=[
                f"No security profile intersection between device supported {list(supported_set)} "
                f"and policy approved {list(approved_set)}"
            ],
        )

    # 4. Filter feasible profiles by memory requirement
    memory_feasible: list[str] = []
    insufficient_ram_profiles: list[str] = []

    for profile in candidate_profiles:
        required_ram = PROFILE_RAM_REQUIREMENTS.get(profile, 32 * 1024)
        if device.ram_bytes_available >= required_ram:
            memory_feasible.append(profile)
        else:
            insufficient_ram_profiles.append(profile)

    if not memory_feasible:
        return ReadinessResult(
            status=ReadinessStatus.NOT_READY,
            feasible_profiles=[],
            recommended_profile=None,
            reasons=[
                f"Device available RAM ({device.ram_bytes_available} B) is insufficient for candidate profiles "
                f"({insufficient_ram_profiles})"
            ],
            available_ram_bytes=device.ram_bytes_available,
        )

    # Sort memory-feasible profiles by highest security rank first
    memory_feasible.sort(
        key=lambda p: (
            MODE_RANK.get(PROFILE_TO_MODE.get(p, ""), 0),
            PROFILE_RAM_REQUIREMENTS.get(p, 0),
        ),
        reverse=True,
    )
    recommended_profile = memory_feasible[0]
    rec_mode = PROFILE_TO_MODE.get(recommended_profile, "CLASSICAL")
    estimated_wire_size = WIRE_SIZE_MAP.get(rec_mode, 1820)
    required_ram = PROFILE_RAM_REQUIREMENTS.get(recommended_profile, 32 * 1024)

    # 5. Fragmentation and MTU check
    requires_fragmentation = False
    if estimated_wire_size > device.max_packet_size_mtu:
        if device.max_packet_size_mtu < 512:
            return ReadinessResult(
                status=ReadinessStatus.NOT_READY,
                feasible_profiles=[],
                recommended_profile=None,
                reasons=[
                    f"Device MTU ({device.max_packet_size_mtu} B) is below minimum safe threshold (512 B) "
                    f"for wire size ({estimated_wire_size} B)"
                ],
                estimated_wire_size=estimated_wire_size,
            )
        requires_fragmentation = True
        reasons.append(
            f"Handshake wire size ({estimated_wire_size} B) exceeds MTU ({device.max_packet_size_mtu} B); "
            f"fragmentation required"
        )

    # 6. Health & Failure history analysis
    recent = device.recent_results
    if recent:
        # Check consecutive failures from the tail of recent results
        consecutive_fails = 0
        consecutive_sec_fails = 0
        for r in reversed(recent):
            outcome = r.get("outcome", "")
            cause = r.get("cause", "")
            if outcome in ("REJECT", "TIMEOUT", "FAILURE"):
                consecutive_fails += 1
                if cause == "security_failure" or outcome == "REJECT":
                    consecutive_sec_fails += 1
            else:
                break

        if consecutive_sec_fails >= consecutive_security_failures_limit:
            return ReadinessResult(
                status=ReadinessStatus.NOT_READY,
                feasible_profiles=[],
                recommended_profile=None,
                reasons=[
                    f"Observed {consecutive_sec_fails} consecutive security failures on device "
                    f"(limit: {consecutive_security_failures_limit})"
                ],
            )

        if consecutive_fails >= max_consecutive_failures:
            reasons.append(
                f"Elevated failure rate: {consecutive_fails} consecutive recent failures observed"
            )
            return ReadinessResult(
                status=ReadinessStatus.PARTIALLY_READY,
                feasible_profiles=memory_feasible,
                recommended_profile=recommended_profile,
                reasons=reasons,
                requires_fragmentation=requires_fragmentation,
                estimated_wire_size=estimated_wire_size,
                available_ram_bytes=device.ram_bytes_available,
                required_ram_bytes=required_ram,
            )

    # If fragmentation is required or any caution reason exists -> PARTIALLY_READY
    if requires_fragmentation:
        return ReadinessResult(
            status=ReadinessStatus.PARTIALLY_READY,
            feasible_profiles=memory_feasible,
            recommended_profile=recommended_profile,
            reasons=reasons,
            requires_fragmentation=True,
            estimated_wire_size=estimated_wire_size,
            available_ram_bytes=device.ram_bytes_available,
            required_ram_bytes=required_ram,
        )

    # Fully ready
    return ReadinessResult(
        status=ReadinessStatus.READY,
        feasible_profiles=memory_feasible,
        recommended_profile=recommended_profile,
        reasons=["Device and flow meet all cryptographic, memory, MTU, and health criteria"],
        requires_fragmentation=False,
        estimated_wire_size=estimated_wire_size,
        available_ram_bytes=device.ram_bytes_available,
        required_ram_bytes=required_ram,
    )
