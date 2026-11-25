"""S3 - Task DEC-3: Approved-Profile-Set Floor Representation

Blueprint GAP-4 / DEC-3: The security floor MUST be expressed as an
*approved profile set* rather than a scalar mode integer.

Rationale (Blueprint §6, §7 GAP-4, §9, §12, Appendix A DEC-3)
--------------------------------------------------------------
The existing scalar ordering (CLASSICAL < HYBRID < PQ) is ambiguous:
  - "HYBRID" covers HYBRID_X25519_MLKEM768 and HYBRID_P256_MLKEM512, which
    have different security margins.
  - Two profiles at the "same" scalar level may differ in algorithm choice,
    parameter set, or regulatory compliance.

The correct representation is a SET of approved profile identifiers taken
directly from the signed policy (the `protection_profiles` field for the
sensitivity tier).  A session is ALLOWED if and only if:

    negotiated_profile ∈ flow_policy.approved_security_profiles

The scalar Mode order is retained as a human-readable summary and for
backwards compatibility with existing code, but it is NOT used as the
authoritative floor check.

Profile identifiers (examples; actual set comes from signed policy)
--------------------------------------------------------------------
"CLASSICAL_RSA2048"
"HYBRID_X25519_MLKEM768"
"HYBRID_P256_MLKEM512"
"PQ_MLKEM768"
"PQ_MLKEM1024"

API
---
ProfileFloor.from_policy(policy_dict) → ProfileFloor
ProfileFloor.check(negotiated_profile) → ProfileFloorResult
ProfileFloor.scalar_summary() → Mode   (for logging / backwards compat only)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Mode (scalar, retained for backwards compatibility only)
# ---------------------------------------------------------------------------

class Mode(IntEnum):
    """Scalar ordering retained for human-readable logging and backwards compat.

    DO NOT use this for the authoritative floor check — use ProfileFloor.check().
    """
    CLASSICAL = 0
    HYBRID    = 1
    PQ        = 2

    @classmethod
    def parse(cls, name: str) -> "Mode":
        aliases = {"PQC": "PQ"}
        normalised = aliases.get(name.upper(), name.upper())
        try:
            return cls[normalised]
        except KeyError:
            raise ValueError(f"unknown_mode:{name!r}")

    @classmethod
    def from_profile(cls, profile: str) -> "Mode":
        """Derive a scalar Mode from a profile string (for logging only)."""
        p = profile.upper()
        if p.startswith("PQ") or p.startswith("MLKEM"):
            return cls.PQ
        if p.startswith("HYBRID"):
            return cls.HYBRID
        return cls.CLASSICAL


# ---------------------------------------------------------------------------
# Profile floor result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProfileFloorResult:
    """Result of a profile membership check."""
    accepted: bool
    negotiated_profile: str
    approved_profiles: frozenset
    scalar_floor: Optional[Mode] = None     # for logging only
    scalar_negotiated: Optional[Mode] = None  # for logging only
    detail: str = ""

    @property
    def is_downgrade(self) -> bool:
        return not self.accepted


# ---------------------------------------------------------------------------
# ProfileFloor (the authoritative floor object)
# ---------------------------------------------------------------------------

@dataclass
class ProfileFloor:
    """An authoritative floor expressed as an approved profile set (DEC-3).

    Constructed from the VERIFIED signed policy — never from device claims.

    Attributes
    ----------
    approved_profiles : frozenset[str]
        The set of profile strings approved by the signed policy for this flow.
        A session is allowed iff negotiated_profile ∈ approved_profiles.
    minimum_scalar_mode : Mode
        Derived scalar summary (for logging and backwards-compat only).
        Never used as the primary gate.
    """
    approved_profiles: frozenset = field(default_factory=frozenset)
    minimum_scalar_mode: Mode = Mode.CLASSICAL

    @classmethod
    def from_policy(cls, policy: dict) -> "ProfileFloor":
        """Build a ProfileFloor from a verified signed-policy dict.

        Expected policy fields (Blueprint §9, §12):
            protection_profiles : list[str]  — approved profile identifiers
            minimum_mode        : str         — scalar fallback (for compat)

        Accepts both S2-style policy dicts (with "protection_profiles" key) and
        minimal dicts with only "minimum_mode" for backwards compatibility.
        """
        raw_profiles: list[str] = policy.get("protection_profiles", [])
        min_mode_str: str = policy.get("minimum_mode", policy.get("floor_mode", "CLASSICAL"))

        try:
            scalar = Mode.parse(min_mode_str)
        except ValueError:
            scalar = Mode.CLASSICAL

        if raw_profiles:
            profiles = frozenset(p.strip().upper() for p in raw_profiles)
            # Derive scalar as the max level in the approved set
            levels = [Mode.from_profile(p) for p in profiles]
            scalar = min(levels)   # floor = minimum approved level
        else:
            # Fallback: synthesise a single-element set from scalar mode
            scalar_name = scalar.name
            profiles = frozenset({scalar_name})

        return cls(approved_profiles=profiles, minimum_scalar_mode=scalar)

    def check(self, negotiated_profile: str) -> ProfileFloorResult:
        """Check whether the negotiated profile is in the approved set.

        Parameters
        ----------
        negotiated_profile : str
            The profile string returned by the ML-KEM / handshake exchange.
            Must come from the gateway, never from the device directly.

        Returns
        -------
        ProfileFloorResult with accepted=True iff negotiated_profile ∈ approved_profiles.
        """
        normalised = negotiated_profile.strip().upper()
        # Also try scalar alias (e.g. "PQ" maps to PQ profiles)
        accepted = normalised in self.approved_profiles

        # Scalar summary for logging
        try:
            scalar_negotiated = Mode.from_profile(normalised)
        except Exception:
            scalar_negotiated = None

        if accepted:
            return ProfileFloorResult(
                accepted=True,
                negotiated_profile=normalised,
                approved_profiles=self.approved_profiles,
                scalar_floor=self.minimum_scalar_mode,
                scalar_negotiated=scalar_negotiated,
                detail=(
                    f"profile={normalised!r} ∈ approved_profiles="
                    f"{set(self.approved_profiles)} — accepted"
                ),
            )
        return ProfileFloorResult(
            accepted=False,
            negotiated_profile=normalised,
            approved_profiles=self.approved_profiles,
            scalar_floor=self.minimum_scalar_mode,
            scalar_negotiated=scalar_negotiated,
            detail=(
                f"PROFILE_DOWNGRADE: {normalised!r} ∉ approved_profiles="
                f"{set(self.approved_profiles)} — session rejected (DEC-3)"
            ),
        )

    def scalar_summary(self) -> Mode:
        """Return the scalar floor level for logging / backwards compat only."""
        return self.minimum_scalar_mode

    def is_reachable_by(self, device_profiles: set[str]) -> bool:
        """Return True if the device can offer at least one approved profile.

        Used for feasibility checks (FloorUnreachable logic).

        Parameters
        ----------
        device_profiles : set[str]
            The set of profiles the device claims it supports (from device registry,
            NOT from the device's handshake offer — the offer is not trusted).
        """
        normalised = {p.strip().upper() for p in device_profiles}
        return bool(normalised & self.approved_profiles)
