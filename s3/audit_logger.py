"""Structured audit logger for the PQC IoT Security Gateway.

Threat-model references
-----------------------
G9   Failures are logged for investigation without leaking sensitive data.
T36  Log injection or log flooding hides attacks or leaks data.
     Mitigation: structured logs; no secrets or payloads in logs; log rate limits.

Design rules (enforced by this module)
---------------------------------------
1.  STRUCTURED: Every log record is a JSON object with a fixed schema so it
    can be parsed by a SIEM or metrics pipeline without regex heuristics.
2.  NO SECRETS: Cryptographic key material, payloads, and raw signatures are
    never written.  Only opaque identifiers (key_id, session_id, device_id)
    and classification metadata appear in records.
3.  RATE-LIMITED: A per-event-type token-bucket prevents a flood of identical
    errors from saturating the log pipeline or hiding a distinct attack signal.
4.  SEVERITY LEVELS: DEBUG < INFO < WARNING < SECURITY < CRITICAL, where
    SECURITY is a dedicated level for events that must be investigated
    (bad signature, replay, downgrade attempt, etc.).

Audit levels from the policy (audit_level field)
-------------------------------------------------
minimal  -> log only security events and rejects
standard -> + accepted decisions
detailed -> + trace fields
enhanced -> + timing and session-bound fields (CRITICAL tier)

Usage
-----
    from audit_logger import AuditLogger, EventKind

    logger = AuditLogger(audit_level="enhanced")

    logger.log_decision(
        event=EventKind.ACCEPTED,
        device_id="phone-01",
        tier="CRITICAL",
        mode="PQ",
        policy_version=7,
        trace=["tier=CRITICAL", "mode=PQ"],
    )

    logger.log_security_event(
        event=EventKind.REPLAY_DETECTED,
        device_id="phone-01",
        session_id="s-abc",
        detail="sequence_number=42",
    )
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, TextIO

# ---------------------------------------------------------------------------
# Severity and event taxonomy
# ---------------------------------------------------------------------------

SECURITY_LEVEL = 35   # between WARNING (30) and ERROR (40)
logging.addLevelName(SECURITY_LEVEL, "SECURITY")


class Severity(str, Enum):
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    SECURITY = "SECURITY"
    CRITICAL = "CRITICAL"


class EventKind(str, Enum):
    # --- Positive ---
    ACCEPTED             = "accepted"
    POLICY_LOADED        = "policy_loaded"
    SESSION_ESTABLISHED  = "session_established"
    RECOVERY_RETRY       = "recovery_retry"
    RECOVERY_REFRAGMENT  = "recovery_refragment"

    # --- Operational warnings ---
    FALLBACK_USED        = "fallback_used"
    CATEGORY_MISMATCH    = "category_destination_mismatch"
    RECOVERY_FAILED      = "recovery_failed"

    # --- Security events (always logged, rate-limited separately) ---
    REJECTED_DEVICE      = "rejected_unregistered_device"
    REVOKED_DEVICE       = "rejected_revoked_device"
    BAD_SIGNATURE        = "rejected_bad_signature"
    ROLLBACK_ATTEMPT     = "rejected_rollback_attempt"
    REPLAY_DETECTED      = "rejected_replay"
    DOWNGRADE_ATTEMPT    = "rejected_downgrade_attempt"
    CAPABILITY_MISMATCH  = "rejected_capability_mismatch"
    POLICY_EXPIRED       = "rejected_policy_expired"
    SECURITY_FAILURE     = "security_failure"
    ALGORITHM_CONFUSION  = "rejected_algorithm_confusion"
    MALFORMED_ENVELOPE   = "rejected_malformed_envelope"
    UNKNOWN_FLOW         = "rejected_unknown_flow"

    # --- Critical operational ---
    VERSION_STORE_ERROR  = "version_store_error"
    POLICY_INVALID       = "no_valid_policy"


# Which events must always be written regardless of audit_level.
_ALWAYS_LOG: frozenset[EventKind] = frozenset({
    EventKind.BAD_SIGNATURE,
    EventKind.ROLLBACK_ATTEMPT,
    EventKind.REPLAY_DETECTED,
    EventKind.DOWNGRADE_ATTEMPT,
    EventKind.REVOKED_DEVICE,
    EventKind.SECURITY_FAILURE,
    EventKind.ALGORITHM_CONFUSION,
    EventKind.VERSION_STORE_ERROR,
})

_SEVERITY_MAP: dict[EventKind, Severity] = {
    EventKind.ACCEPTED:             Severity.INFO,
    EventKind.POLICY_LOADED:        Severity.INFO,
    EventKind.SESSION_ESTABLISHED:  Severity.INFO,
    EventKind.RECOVERY_RETRY:       Severity.WARNING,
    EventKind.RECOVERY_REFRAGMENT:  Severity.WARNING,
    EventKind.FALLBACK_USED:        Severity.WARNING,
    EventKind.CATEGORY_MISMATCH:    Severity.WARNING,
    EventKind.RECOVERY_FAILED:      Severity.WARNING,
    EventKind.REJECTED_DEVICE:      Severity.SECURITY,
    EventKind.REVOKED_DEVICE:       Severity.SECURITY,
    EventKind.BAD_SIGNATURE:        Severity.SECURITY,
    EventKind.ROLLBACK_ATTEMPT:     Severity.SECURITY,
    EventKind.REPLAY_DETECTED:      Severity.SECURITY,
    EventKind.DOWNGRADE_ATTEMPT:    Severity.SECURITY,
    EventKind.CAPABILITY_MISMATCH:  Severity.WARNING,
    EventKind.POLICY_EXPIRED:       Severity.WARNING,
    EventKind.SECURITY_FAILURE:     Severity.SECURITY,
    EventKind.ALGORITHM_CONFUSION:  Severity.SECURITY,
    EventKind.MALFORMED_ENVELOPE:   Severity.WARNING,
    EventKind.UNKNOWN_FLOW:         Severity.WARNING,
    EventKind.VERSION_STORE_ERROR:  Severity.CRITICAL,
    EventKind.POLICY_INVALID:       Severity.WARNING,
}

_AUDIT_LEVEL_ORDER = {"minimal": 0, "standard": 1, "detailed": 2, "enhanced": 3}
# Which audit_level enables logging INFO events (SECURITY always logs).
_INFO_THRESHOLD = {"minimal": False, "standard": True, "detailed": True, "enhanced": True}


# ---------------------------------------------------------------------------
# Rate limiter (token bucket per event kind)
# ---------------------------------------------------------------------------

@dataclass
class _Bucket:
    capacity: int
    tokens: float
    refill_per_sec: float
    last_refill: float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def consume(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
            self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Structured, rate-limited, secret-free audit logger.

    Parameters
    ----------
    audit_level:
        One of 'minimal', 'standard', 'detailed', 'enhanced'.
        Controls verbosity for non-security INFO events.
    rate_limit_per_min:
        Approximate maximum log records per minute per EventKind.
        Set to 0 to disable rate limiting (tests only).
    sink:
        File-like object to write JSON records to. Defaults to sys.stdout.
    gateway_id:
        Optional identifier added to every record.
    """

    def __init__(
        self,
        audit_level: str = "standard",
        rate_limit_per_min: int = 120,
        sink: Optional[TextIO] = None,
        gateway_id: str = "gateway",
    ):
        if audit_level not in _AUDIT_LEVEL_ORDER:
            raise ValueError(f"unknown audit_level: {audit_level!r}")
        self._level = audit_level
        self._rate_limit = rate_limit_per_min
        self._sink = sink or sys.stdout
        self._gateway_id = gateway_id
        self._lock = threading.Lock()
        self._buckets: dict[EventKind, _Bucket] = {}
        self._suppressed: dict[EventKind, int] = {}
        self.counters: dict[str, int] = {}

    # ------------------------------------------------------------------ public

    def log_decision(
        self,
        event: EventKind,
        *,
        device_id: str,
        tier: Optional[str] = None,
        mode: Optional[str] = None,
        policy_version: Optional[int] = None,
        reject_reason: Optional[str] = None,
        fallback_used: bool = False,
        trace: Optional[list[str]] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log a classifier/policy decision event."""
        fields: dict[str, Any] = {"device_id": device_id}
        if tier is not None:
            fields["tier"] = tier
        if mode is not None:
            fields["mode"] = mode
        if policy_version is not None:
            fields["policy_version"] = policy_version
        if reject_reason is not None:
            fields["reject_reason"] = reject_reason
        if fallback_used:
            fields["fallback_used"] = True
        if trace is not None and _AUDIT_LEVEL_ORDER[self._level] >= 2:  # detailed+
            fields["trace"] = trace
        if extra:
            fields.update(extra)
        self._emit(event, fields)

    def log_security_event(
        self,
        event: EventKind,
        *,
        device_id: Optional[str] = None,
        session_id: Optional[str] = None,
        detail: Optional[str] = None,
        policy_version: Optional[int] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log a security event.  Always written (never suppressed by audit_level)."""
        fields: dict[str, Any] = {}
        if device_id is not None:
            fields["device_id"] = device_id
        if session_id is not None:
            fields["session_id"] = session_id
        if detail is not None:
            fields["detail"] = detail
        if policy_version is not None:
            fields["policy_version"] = policy_version
        if extra:
            fields.update(extra)
        self._emit(event, fields, force=True)

    def log_policy_event(
        self,
        event: EventKind,
        *,
        policy_version: Optional[int] = None,
        key_id: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        """Log a policy lifecycle event (load, expiry, rollback, etc.)."""
        fields: dict[str, Any] = {}
        if policy_version is not None:
            fields["policy_version"] = policy_version
        if key_id is not None:
            fields["key_id"] = key_id   # opaque identifier only, not the key bytes
        if detail is not None:
            fields["detail"] = detail
        self._emit(event, fields, force=(event in _ALWAYS_LOG))

    def log_recovery(
        self,
        event: EventKind,
        *,
        session_id: str,
        cause: str,
        attempt: int,
        backoff_ms: int = 0,
    ) -> None:
        """Log a recovery action."""
        fields: dict[str, Any] = {
            "session_id": session_id,
            "cause": cause,
            "attempt": attempt,
        }
        if backoff_ms:
            fields["backoff_ms"] = backoff_ms
        self._emit(event, fields)

    def log_gateway_decision(
        self,
        *,
        device_id: str,
        flow_id: str,
        sensitivity: Optional[str],
        minimum_mode: Optional[str],
        requested_mode: str,
        policy_version: Optional[int],
        decision: str,
        reason: str,
        cause_label: Optional[str] = None,
        s3_verdict: Optional[str] = None,
    ) -> None:
        """Emit a log record whose schema matches both S2's gateway_logs.jsonl
        and S4's unified log schema (§A of S4_data_science_evaluation.md).

        S2 gateway_logs.jsonl fields (all present):
            timestamp, device_id, flow_id, sensitivity, minimum_mode,
            requested_mode, policy_version, decision, reason

        Additional S4 fields (present when supplied):
            cause_label  – S3 CauseClass value string (e.g. "security_failure")
            s3_verdict   – ControllerVerdict name (e.g. "DISCARD_AND_LOG")

        This method writes to the AuditLogger sink (which may be stdout or a
        file), NOT to S2's gateway_logs.jsonl file.  S2 writes its own file;
        this method exists so that S3 can emit equivalent structured records
        that S4's parser can read from a single unified stream.

        Always written (force=True) — gateway decisions are never suppressed.
        """
        # Determine severity: ALLOW → INFO, FLOOR_UNREACHABLE → SECURITY, else WARNING
        if decision == "ALLOW":
            event = EventKind.ACCEPTED
        elif decision == "FLOOR_UNREACHABLE":
            event = EventKind.SECURITY_FAILURE
        else:
            event = EventKind.REJECTED_DEVICE

        fields: dict[str, Any] = {
            "device_id": device_id,
            "flow_id": flow_id,
            "sensitivity": sensitivity,
            "minimum_mode": minimum_mode,
            "requested_mode": requested_mode,
            "policy_version": policy_version,
            "decision": decision,
            "reason": reason,
        }
        if cause_label is not None:
            fields["cause_label"] = cause_label
        if s3_verdict is not None:
            fields["s3_verdict"] = s3_verdict

        self._emit(event, fields, force=True)

    def metrics_snapshot(self) -> dict[str, int]:
        """Return a copy of the current counter snapshot for metrics pipelines."""
        with self._lock:
            return dict(self.counters)

    # ----------------------------------------------------------------- private

    def _should_log(self, event: EventKind, force: bool) -> bool:
        """Return True if this event should be written given current audit_level."""
        if force or event in _ALWAYS_LOG:
            return True
        severity = _SEVERITY_MAP.get(event, Severity.INFO)
        if severity in (Severity.SECURITY, Severity.CRITICAL):
            return True
        if severity == Severity.WARNING:
            return True  # warnings always written
        # INFO events: depends on audit_level
        return _INFO_THRESHOLD.get(self._level, False)

    def _rate_ok(self, event: EventKind) -> bool:
        """Return True if the token bucket allows this record."""
        if self._rate_limit == 0:
            return True
        if event not in self._buckets:
            rps = self._rate_limit / 60.0
            self._buckets[event] = _Bucket(
                capacity=max(1, self._rate_limit // 10),
                tokens=float(max(1, self._rate_limit // 10)),
                refill_per_sec=rps,
            )
        return self._buckets[event].consume()

    def _emit(
        self,
        event: EventKind,
        fields: dict[str, Any],
        force: bool = False,
    ) -> None:
        if not self._should_log(event, force):
            return

        severity = _SEVERITY_MAP.get(event, Severity.INFO)

        with self._lock:
            # Rate limiting (security events bypass the suppressor).
            is_security = severity in (Severity.SECURITY, Severity.CRITICAL)
            if not is_security and not self._rate_ok(event):
                self._suppressed[event] = self._suppressed.get(event, 0) + 1
                return

            # Counters.
            self.counters[event.value] = self.counters.get(event.value, 0) + 1

            record: dict[str, Any] = {
                "ts": _now_iso(),
                "gw": self._gateway_id,
                "event": event.value,
                "severity": severity.value,
                **fields,
            }

            suppressed = self._suppressed.pop(event, 0)
            if suppressed:
                record["suppressed_before_this"] = suppressed

            try:
                self._sink.write(json.dumps(record, separators=(",", ":")) + "\n")
                self._sink.flush()
            except OSError:
                pass  # Best-effort; never crash the gateway for a log failure.


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string (no external dependency)."""
    t = time.gmtime()
    return (
        f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}T"
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}Z"
    )
