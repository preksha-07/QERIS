"""S3 - Task DEC-4: Policy Epoch Safety (Invariant I8)

Prevents TOCTOU (Time-Of-Check-Time-Of-Use) violations that occur when a
policy update (e.g. policy v6) arrives WHILE a handshake that was authorised
under an older policy (e.g. policy v5) is still in flight.

Invariant I8 (Blueprint §17, §GAP-6):
    "No flow may be activated under a policy that is no longer the current
    applicable policy for that flow."

Design (Blueprint §8 Steps 5–10, §12 Transition table, §23 A11–A13)
--------------------------------------------------------------------
Every in-flight handshake is bound to a *context record* at the moment the
gateway authorises it.  When the handshake completes (HandshakeOk), the
activation check compares the bound epoch to the currently live epoch:

    epoch_match   → compliant rebind   → ACTIVATE normally
    epoch_mismatch AND new policy compat → incompatible restart → restart handshake
    epoch_mismatch AND new policy incompat → impossible quarantine → QUARANTINE

The I8 check is a pure function; the gateway calls it, then acts on the result.
No I/O inside this module.

Context binding record fields
------------------------------
device_id          : str
flow_id            : str
epoch              : int            (policy version at authorisation time)
policy_digest      : str            (hex-encoded hash of policy bytes at auth time)
approved_profiles  : frozenset[str] (the floor profile set at auth time)
handshake_id       : str            (unique token for this handshake attempt)

ActivationOutcome variants
---------------------------
COMPLIANT_REBIND    : epoch matches; activate normally.
INCOMPATIBLE_RESTART: epoch changed but new policy allows negotiated profile; restart.
IMPOSSIBLE_QUARANTINE: epoch changed AND new policy forbids negotiated profile; quarantine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import hashlib


# ---------------------------------------------------------------------------
# Activation outcome
# ---------------------------------------------------------------------------

class ActivationOutcome(Enum):
    """Result of the I8 epoch-safety check at activation time."""
    COMPLIANT_REBIND       = "compliant_rebind"
    INCOMPATIBLE_RESTART   = "incompatible_restart"
    IMPOSSIBLE_QUARANTINE  = "impossible_quarantine"


@dataclass(frozen=True)
class ActivationCheckResult:
    outcome: ActivationOutcome
    device_id: str
    flow_id: str
    handshake_id: str
    bound_epoch: int
    live_epoch: int
    negotiated_profile: str
    detail: str = ""

    @property
    def should_activate(self) -> bool:
        return self.outcome is ActivationOutcome.COMPLIANT_REBIND

    @property
    def should_restart(self) -> bool:
        return self.outcome is ActivationOutcome.INCOMPATIBLE_RESTART

    @property
    def should_quarantine(self) -> bool:
        return self.outcome is ActivationOutcome.IMPOSSIBLE_QUARANTINE


# ---------------------------------------------------------------------------
# Context binding record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HandshakeContextRecord:
    """Immutable record created when the gateway authorises a handshake attempt.

    The gateway creates one of these the moment it approves a HandshakeStarted
    event and passes it into activation_check() when HandshakeOk arrives.

    Fields
    ------
    device_id         : Device identifier.
    flow_id           : Flow identifier.
    epoch             : Policy version that was current when this handshake
                        was authorised (policy_version from FlowContext).
    policy_digest     : SHA-256 hex digest of the raw policy bytes at auth time.
                        Used to detect byte-level tampering between auth and use.
    approved_profiles : Frozenset of approved security profile strings at auth time
                        (DEC-3 representation: e.g. {"HYBRID_X25519_MLKEM768", "PQ_MLKEM768"}).
    handshake_id      : Unique opaque token for this handshake attempt (UUID or nonce).
    """
    device_id: str
    flow_id: str
    epoch: int
    policy_digest: str
    approved_profiles: frozenset
    handshake_id: str

    @classmethod
    def create(
        cls,
        device_id: str,
        flow_id: str,
        epoch: int,
        policy_bytes: bytes,
        approved_profiles: set[str],
        handshake_id: str,
    ) -> "HandshakeContextRecord":
        """Factory: computes digest from policy_bytes automatically."""
        digest = hashlib.sha256(policy_bytes).hexdigest()
        return cls(
            device_id=device_id,
            flow_id=flow_id,
            epoch=epoch,
            policy_digest=digest,
            approved_profiles=frozenset(approved_profiles),
            handshake_id=handshake_id,
        )


# ---------------------------------------------------------------------------
# Live policy snapshot (provided by gateway at activation check time)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LivePolicySnapshot:
    """Snapshot of the currently-live policy for a flow at activation time.

    The gateway creates this from its current state just before calling
    activation_check().  It is NOT the same object as the HandshakeContextRecord
    — it reflects what is live *now*, not what was authorised earlier.

    Fields
    ------
    epoch             : Currently live policy version.
    policy_digest     : SHA-256 hex digest of the current policy bytes.
    approved_profiles : Currently approved security profile set (DEC-3).
    """
    epoch: int
    policy_digest: str
    approved_profiles: frozenset

    @classmethod
    def create(
        cls,
        epoch: int,
        policy_bytes: bytes,
        approved_profiles: set[str],
    ) -> "LivePolicySnapshot":
        digest = hashlib.sha256(policy_bytes).hexdigest()
        return cls(
            epoch=epoch,
            policy_digest=digest,
            approved_profiles=frozenset(approved_profiles),
        )


# ---------------------------------------------------------------------------
# I8 Activation Check (pure function)
# ---------------------------------------------------------------------------

def activation_check(
    record: HandshakeContextRecord,
    live: LivePolicySnapshot,
    negotiated_profile: str,
) -> ActivationCheckResult:
    """Invariant I8 check: validate a completed handshake against live policy.

    This is a PURE FUNCTION — no I/O.  The gateway calls it on HandshakeOk
    and acts on the ActivationCheckResult.

    Parameters
    ----------
    record             : Context record bound at HandshakeStarted authorisation.
    live               : Currently-live policy snapshot (fetched just before this call).
    negotiated_profile : The security profile string actually negotiated in the handshake
                         (e.g. "PQ_MLKEM768", "HYBRID_X25519_MLKEM768").

    Returns
    -------
    ActivationCheckResult with outcome:
        COMPLIANT_REBIND       — epochs match; profile still approved; activate.
        INCOMPATIBLE_RESTART   — epoch changed; new policy allows the profile; restart handshake.
        IMPOSSIBLE_QUARANTINE  — epoch changed; new policy forbids the profile; quarantine.

    Invariant I8 enforcement
    ------------------------
    If record.epoch != live.epoch, the policy changed during the handshake.
    We MUST NOT activate under the stale authorisation.  Instead:
      • If the negotiated_profile is in live.approved_profiles → restart cleanly.
      • If the negotiated_profile is NOT in live.approved_profiles → quarantine.
    Either way, the stale-authorisation path is NEVER used to activate.
    """
    # --- Case 1: epoch unchanged → verify digest integrity then activate ---
    if record.epoch == live.epoch:
        # Secondary check: policy bytes must not have changed between auth and use
        if record.policy_digest != live.policy_digest:
            # Digest mismatch with same epoch: policy mutated in place (tamper or bug).
            # Treat as epoch change → check profile against live set.
            if negotiated_profile in live.approved_profiles:
                return ActivationCheckResult(
                    outcome=ActivationOutcome.INCOMPATIBLE_RESTART,
                    device_id=record.device_id,
                    flow_id=record.flow_id,
                    handshake_id=record.handshake_id,
                    bound_epoch=record.epoch,
                    live_epoch=live.epoch,
                    negotiated_profile=negotiated_profile,
                    detail=(
                        f"I8: epoch={record.epoch} matches but digest mismatch "
                        f"(bound={record.policy_digest[:8]}… "
                        f"live={live.policy_digest[:8]}…) — "
                        "policy mutated in place; restarting handshake."
                    ),
                )
            return ActivationCheckResult(
                outcome=ActivationOutcome.IMPOSSIBLE_QUARANTINE,
                device_id=record.device_id,
                flow_id=record.flow_id,
                handshake_id=record.handshake_id,
                bound_epoch=record.epoch,
                live_epoch=live.epoch,
                negotiated_profile=negotiated_profile,
                detail=(
                    f"I8: epoch={record.epoch} matches but digest mismatch AND "
                    f"negotiated profile {negotiated_profile!r} NOT in live approved "
                    f"set {set(live.approved_profiles)} — quarantining."
                ),
            )

        # Epoch and digest both match — compliant rebind
        if negotiated_profile not in record.approved_profiles:
            # Profile was not in the approved set even at authorisation time
            # (should have been caught earlier, but be paranoid here)
            return ActivationCheckResult(
                outcome=ActivationOutcome.IMPOSSIBLE_QUARANTINE,
                device_id=record.device_id,
                flow_id=record.flow_id,
                handshake_id=record.handshake_id,
                bound_epoch=record.epoch,
                live_epoch=live.epoch,
                negotiated_profile=negotiated_profile,
                detail=(
                    f"I8: profile {negotiated_profile!r} not in auth-time approved "
                    f"set {set(record.approved_profiles)} — quarantining."
                ),
            )
        return ActivationCheckResult(
            outcome=ActivationOutcome.COMPLIANT_REBIND,
            device_id=record.device_id,
            flow_id=record.flow_id,
            handshake_id=record.handshake_id,
            bound_epoch=record.epoch,
            live_epoch=live.epoch,
            negotiated_profile=negotiated_profile,
            detail=(
                f"I8: epoch={record.epoch}, digest=…{record.policy_digest[:8]}, "
                f"profile={negotiated_profile!r} ∈ approved_profiles — activate."
            ),
        )

    # --- Case 2: epoch changed during handshake (TOCTOU risk) ---------------
    # Policy version changed between HandshakeStarted (auth) and HandshakeOk.
    # We MUST NOT use the stale authorisation.  Classify by profile membership
    # under the NEW (live) policy.

    if negotiated_profile in live.approved_profiles:
        return ActivationCheckResult(
            outcome=ActivationOutcome.INCOMPATIBLE_RESTART,
            device_id=record.device_id,
            flow_id=record.flow_id,
            handshake_id=record.handshake_id,
            bound_epoch=record.epoch,
            live_epoch=live.epoch,
            negotiated_profile=negotiated_profile,
            detail=(
                f"I8: epoch changed {record.epoch}→{live.epoch} during handshake; "
                f"profile {negotiated_profile!r} IS in new approved set — "
                "incompatible restart (re-authorise under new policy)."
            ),
        )

    return ActivationCheckResult(
        outcome=ActivationOutcome.IMPOSSIBLE_QUARANTINE,
        device_id=record.device_id,
        flow_id=record.flow_id,
        handshake_id=record.handshake_id,
        bound_epoch=record.epoch,
        live_epoch=live.epoch,
        negotiated_profile=negotiated_profile,
        detail=(
            f"I8: epoch changed {record.epoch}→{live.epoch} during handshake; "
            f"profile {negotiated_profile!r} NOT in new approved set "
            f"{set(live.approved_profiles)} — impossible quarantine."
        ),
    )


# ---------------------------------------------------------------------------
# PolicyEpochChanged event helper (for state machine integration)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyEpochChangedEvent:
    """Gateway emits this when a new policy is verified while a handshake is in-flight.

    The state machine receives this event alongside the HandshakeOk event.
    The gateway MUST call activation_check() first, then route to the state machine
    based on the ActivationOutcome.

    Fields
    ------
    old_epoch    : Policy version that was current at HandshakeStarted.
    new_epoch    : Currently live policy version.
    flow_id      : Flow affected.
    """
    old_epoch: int
    new_epoch: int
    flow_id: str

    @property
    def is_change(self) -> bool:
        return self.old_epoch != self.new_epoch
