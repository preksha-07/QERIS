"""S3 - Task T17: Downgrade Rejection

Enforces that the mode negotiated for a session is NEVER below the security
floor specified in the signed policy for that flow.

Design (from S3 spec §E, threat model T18, T05, T33)
-----------------------------------------------------
The floor comes exclusively from the VERIFIED signed policy
(`minimum_mode` field, or the equivalent `protection_profiles` entry for the
sensitivity tier).  It is NEVER taken from:
  - what the device claims its mode is
  - what the device reports its capabilities to be
  - the mode the device offers during handshake

Comparison uses a strict partial order on the three modes:
    CLASSICAL (0) < HYBRID (1) < PQ (2)

If negotiated_mode < floor_mode the gateway MUST:
  1. Reject the session immediately.
  2. Emit a SECURITY_FAILURE event to the state machine.
  3. Log the attempt (forwarded to audit_logger).
  4. NEVER fall back to the device's requested mode.

The invariant (Invariant 1): a flow is never Active below its signed floor.

S2 interoperability note
------------------------
S2's gateway.py and policy.json use the string "PQC" for the highest mode
(SECURITY_LEVEL = {"CLASSICAL": 1, "HYBRID": 2, "PQC": 3}).
S3 uses the canonical internal name "PQ" for the same level.
Mode.parse() normalises "PQC" → "PQ" transparently so that S2 mode strings
can be passed directly to any S3 function without prior translation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Mode ordering
# ---------------------------------------------------------------------------

# Canonical alias: S2 uses "PQC"; S3 uses "PQ" internally.
_S2_ALIASES: dict[str, str] = {"PQC": "PQ"}


class Mode(IntEnum):
    """Strict ordering: CLASSICAL < HYBRID < PQ.

    Accepts the S2 alias "PQC" in Mode.parse() — it resolves to Mode.PQ.
    """
    CLASSICAL = 0
    HYBRID    = 1
    PQ        = 2

    @classmethod
    def parse(cls, name: str) -> "Mode":
        """Parse a mode string into a Mode enum value.

        Accepts both S3-canonical names (CLASSICAL, HYBRID, PQ) and the S2
        alias (PQC → PQ).  Case-insensitive.

        Raises ValueError for any unrecognised name.
        """
        normalised = name.upper()
        # Resolve S2 alias before lookup
        normalised = _S2_ALIASES.get(normalised, normalised)
        try:
            return cls[normalised]
        except KeyError:
            raise ValueError(f"unknown_mode:{name!r}")


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DowngradeCheckResult:
    accepted: bool
    negotiated: Mode
    floor: Mode
    detail: str = ""

    @property
    def is_downgrade(self) -> bool:
        return not self.accepted


# ---------------------------------------------------------------------------
# Downgrade rejection
# ---------------------------------------------------------------------------

class DowngradeRejector:
    """Checks every negotiated mode against the policy floor.

    The floor is always read from the verified policy, never from the device.

    Usage
    -----
        rejector = DowngradeRejector()
        result = rejector.check(negotiated_mode="HYBRID", floor_mode="PQ")
        if result.is_downgrade:
            # forward SecurityFailure(DOWNGRADE_ATTEMPT) to state machine
    """

    def check(
        self,
        negotiated_mode: str | Mode,
        floor_mode: str | Mode,
    ) -> DowngradeCheckResult:
        """Return a DowngradeCheckResult.

        Parameters
        ----------
        negotiated_mode:
            The mode that was actually negotiated in the handshake
            (e.g. from the ML-KEM exchange result).
        floor_mode:
            The minimum allowed mode for this flow from the signed policy.
            MUST come from the verified policy, not the device.
        """
        if isinstance(negotiated_mode, str):
            negotiated_mode = Mode.parse(negotiated_mode)
        if isinstance(floor_mode, str):
            floor_mode = Mode.parse(floor_mode)

        if negotiated_mode >= floor_mode:
            return DowngradeCheckResult(
                accepted=True,
                negotiated=negotiated_mode,
                floor=floor_mode,
                detail=(
                    f"mode={negotiated_mode.name} >= floor={floor_mode.name}: accepted"
                ),
            )
        return DowngradeCheckResult(
            accepted=False,
            negotiated=negotiated_mode,
            floor=floor_mode,
            detail=(
                f"DOWNGRADE: negotiated={negotiated_mode.name} "
                f"< floor={floor_mode.name} — session rejected"
            ),
        )

    def check_floor_reachable(
        self,
        floor_mode: str | Mode,
        device_best_mode: str | Mode,
    ) -> bool:
        """Return True if the device can physically reach the floor.

        If False, the controller must return FloorUnreachable and stop
        retrying instead of looping forever. (S3 spec §D)
        """
        if isinstance(floor_mode, str):
            floor_mode = Mode.parse(floor_mode)
        if isinstance(device_best_mode, str):
            device_best_mode = Mode.parse(device_best_mode)
        return device_best_mode >= floor_mode
