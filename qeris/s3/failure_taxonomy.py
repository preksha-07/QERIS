"""S3 - Task T19: Failure Taxonomy

Defines the canonical cause classes, observable signal→cause mapping rules,
and structured event schema that the gateway uses to classify every handshake
or transport failure.

Design principles (from S3 spec §C and threat model §6.6)
----------------------------------------------------------
1.  Classification is determined by the VERIFICATION RESULT, never by timing
    alone.  A message that fails an authentication check is SECURITY_FAILURE
    even if it also arrived late.  (Threat T48)
2.  Causes are mutually exclusive per event; the classifier picks the first
    matching rule in priority order (security > mtu > loss).
3.  Every classified event is stamped with its cause, signals observed, and a
    label_confidence so S4 can compare against injected ground truth.
4.  The COMPUTE cause class is conditional: it is included only when resource
    exhaustion signals are actually observed in pilot data.  If not observed,
    it is dropped and the paper says so honestly (S3 spec §C §66).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ---------------------------------------------------------------------------
# Cause taxonomy
# ---------------------------------------------------------------------------

class CauseClass(Enum):
    """Canonical cause classes.

    Priority order for classification (highest wins):
      SECURITY_FAILURE > MTU_FRAGMENT > LOSS_TIMEOUT > COMPUTE (if enabled)
    """
    SECURITY_FAILURE = "security_failure"
    # Bad signature, unknown authority, stale/replayed version, mode below floor.
    # ALWAYS terminal — never triggers a retry at any mode. (T48)

    MTU_FRAGMENT = "mtu_fragment"
    # Fragment count or size exceeds path MTU; fragments repeatedly dropped.
    # PQ keys and ciphertexts are large and frequently cause this.

    LOSS_TIMEOUT = "loss_timeout"
    # No response; retransmit timer expires; fragments missing with no auth failure.

    COMPUTE = "compute"
    # Peer alive but response arrives only after excessive delay; long key-generation
    # time reported.  Include only if observed in Week-1 pilot data; otherwise drop.


# Sub-reasons for SECURITY_FAILURE — forwarded to audit_logger and S4.
class SecurityReason(Enum):
    BAD_SIGNATURE        = "bad_signature"
    UNKNOWN_AUTHORITY    = "unknown_authority"
    STALE_VERSION        = "stale_version"           # version == persisted highest
    REPLAYED_VERSION     = "replayed_version"         # version < persisted highest
    FAST_FORWARD_VERSION = "fast_forward_version"     # version jump > max_version_jump
    MODE_BELOW_FLOOR     = "mode_below_floor"
    INVALID_FORMAT       = "invalid_format"
    REVOKED_ALGORITHM    = "revoked_algorithm"
    DOWNGRADE_ATTEMPT    = "downgrade_attempt"


# ---------------------------------------------------------------------------
# Observable signals
# ---------------------------------------------------------------------------

@dataclass
class ObservedSignals:
    """Signals visible to the gateway at the point of failure.

    All fields are optional — populate only what the gateway can observe.
    S4 uses these alongside the injected ground truth to measure classifier
    accuracy.
    """
    # Transport-layer signals
    no_response: bool = False           # retransmit timer expired, no reply
    fragments_missing: bool = False     # incomplete fragment set received
    fragment_size_exceeded: bool = False  # fragment > negotiated MTU
    fragment_count_exceeded: bool = False  # too many fragments for one message
    repeated_fragment_drop: bool = False   # same fragment dropped >1 times

    # Timing signals
    response_delay_ms: Optional[int] = None  # observed RTT/response delay
    keygen_delay_ms: Optional[int] = None    # reported key-generation time

    # Cryptographic / policy signals
    auth_check_failed: bool = False     # AEAD tag bad or ML-DSA verify failed
    version_check_failed: bool = False  # incoming version <= persisted highest
    version_jump_exceeded: bool = False # incoming version > highest + max_jump
    mode_below_floor: bool = False      # negotiated mode < policy floor
    unknown_authority: bool = False     # issuer key not pinned
    revoked_algorithm: bool = False     # algorithm on the revoked list
    invalid_format: bool = False        # parse error, malformed envelope

    # Threshold for "compute" classification (ms).
    # Populated from pilot measurement; None means compute class is disabled.
    compute_delay_threshold_ms: Optional[int] = None

    # ------------------------------------------------------------------
    # S1 bridge: PolicyVerificationStatus → ObservedSignals
    # ------------------------------------------------------------------

    @classmethod
    def from_s1_status(cls, status: str) -> "ObservedSignals":
        """Translate an S1 PolicyVerificationStatus string into ObservedSignals.

        S1's verify_policy() returns a PolicyVerificationResult whose .status
        attribute is a PolicyVerificationStatus enum value with these names:

            VALID               – not a failure; return empty signals
            INVALID_STRUCTURE   – malformed policy bytes / fields
            INVALID_SIGNATURE   – ML-DSA signature check failed
            STALE_POLICY        – version < last_seen (anti-rollback)
            WRONG_ALGORITHM     – sig_alg not in allowed_algorithms
            UNSUPPORTED_ALGORITHM – algorithm not in local liboqs

        Caller passes `result.status.name` (or the string value) and gets
        back a populated ObservedSignals that the classifier can immediately
        route to the correct CauseClass / SecurityReason.

        Usage::

            result = verify_policy(policy_bytes, sig, pub_key,
                                   last_seen_version=last_ver)
            if not result.is_valid:
                signals = ObservedSignals.from_s1_status(result.status.name)
                event   = FailureTaxonomy().classify(signals)
                # → always SECURITY_FAILURE with the right SecurityReason
        """
        key = status.upper()
        if key == "INVALID_STRUCTURE":
            return cls(invalid_format=True)
        if key == "INVALID_SIGNATURE":
            return cls(auth_check_failed=True)
        if key == "STALE_POLICY":
            # version < last_seen → replay / rollback attempt
            return cls(version_check_failed=True)
        if key in ("WRONG_ALGORITHM", "UNSUPPORTED_ALGORITHM"):
            return cls(revoked_algorithm=True)
        # VALID or anything unrecognised → no failure signals
        return cls()


# ---------------------------------------------------------------------------
# Classified event (the output of the taxonomy)
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedEvent:
    """Result of classifying a failure event.

    This is the record forwarded to:
    - audit_logger  (for security logging)
    - RecoveryController (to select the allowed action set)
    - S4 (for confusion-matrix evaluation against ground truth)
    """
    cause: CauseClass
    security_reason: Optional[SecurityReason] = None  # set iff SECURITY_FAILURE
    signals: ObservedSignals = field(default_factory=ObservedSignals)
    label_confidence: str = "high"   # "high" | "medium" | "low"
    notes: str = ""

    def is_security(self) -> bool:
        return self.cause is CauseClass.SECURITY_FAILURE

    def to_dict(self) -> dict:
        """Structured dict for audit_logger and S4 schema."""
        d: dict = {
            "cause": self.cause.value,
            "label_confidence": self.label_confidence,
        }
        if self.security_reason:
            d["security_reason"] = self.security_reason.value
        if self.notes:
            d["notes"] = self.notes
        return d


# ---------------------------------------------------------------------------
# Classifier: signal → cause
# ---------------------------------------------------------------------------

class FailureTaxonomy:
    """Maps observed signals to a CauseClass.

    Rule table (priority order — first match wins):

    | Signal                                  | Cause            |
    |-----------------------------------------|------------------|
    | auth_check_failed                       | SECURITY_FAILURE |
    | version_check_failed                    | SECURITY_FAILURE |
    | version_jump_exceeded                   | SECURITY_FAILURE |
    | mode_below_floor                        | SECURITY_FAILURE |
    | unknown_authority                       | SECURITY_FAILURE |
    | revoked_algorithm                       | SECURITY_FAILURE |
    | invalid_format                          | SECURITY_FAILURE |
    | fragment_size_exceeded OR               |                  |
    |   fragment_count_exceeded OR            |                  |
    |   repeated_fragment_drop                | MTU_FRAGMENT     |
    | response_delay_ms > compute_threshold   | COMPUTE (if set) |
    | no_response OR fragments_missing        | LOSS_TIMEOUT     |
    | (fallback)                              | LOSS_TIMEOUT     |
    """

    def classify(self, signals: ObservedSignals) -> ClassifiedEvent:
        """Return a ClassifiedEvent for the given ObservedSignals."""

        # --- Priority 1: Security checks (cryptographic / policy) ---
        if signals.auth_check_failed:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.BAD_SIGNATURE,
                signals=signals,
                label_confidence="high",
                notes="AEAD tag or ML-DSA signature verification failed",
            )
        if signals.unknown_authority:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.UNKNOWN_AUTHORITY,
                signals=signals,
                label_confidence="high",
            )
        if signals.revoked_algorithm:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.REVOKED_ALGORITHM,
                signals=signals,
                label_confidence="high",
            )
        if signals.invalid_format:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.INVALID_FORMAT,
                signals=signals,
                label_confidence="high",
            )
        if signals.mode_below_floor:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.MODE_BELOW_FLOOR,
                signals=signals,
                label_confidence="high",
                notes="Negotiated mode is below the signed policy floor",
            )
        if signals.version_jump_exceeded:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.FAST_FORWARD_VERSION,
                signals=signals,
                label_confidence="high",
                notes="Version jump exceeds max_version_jump — possible freeze attack",
            )
        if signals.version_check_failed:
            return ClassifiedEvent(
                cause=CauseClass.SECURITY_FAILURE,
                security_reason=SecurityReason.REPLAYED_VERSION,
                signals=signals,
                label_confidence="high",
                notes="Incoming version <= persisted highest — replay/rollback attempt",
            )

        # --- Priority 2: MTU / fragmentation ---
        if (signals.fragment_size_exceeded
                or signals.fragment_count_exceeded
                or signals.repeated_fragment_drop):
            return ClassifiedEvent(
                cause=CauseClass.MTU_FRAGMENT,
                signals=signals,
                label_confidence="high",
            )

        # --- Priority 3: Compute (conditional) ---
        if (signals.compute_delay_threshold_ms is not None
                and signals.response_delay_ms is not None
                and signals.response_delay_ms > signals.compute_delay_threshold_ms):
            return ClassifiedEvent(
                cause=CauseClass.COMPUTE,
                signals=signals,
                label_confidence="medium",
                notes=(
                    f"response_delay={signals.response_delay_ms}ms "
                    f"> threshold={signals.compute_delay_threshold_ms}ms"
                ),
            )

        # --- Priority 4: Loss / timeout (default) ---
        return ClassifiedEvent(
            cause=CauseClass.LOSS_TIMEOUT,
            signals=signals,
            label_confidence="high" if signals.no_response else "medium",
        )
