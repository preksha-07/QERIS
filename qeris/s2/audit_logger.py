"""
QERIS S2: Structured Gateway Audit Logger

Writes machine-readable JSONL audit records aligning with S4 log_schema.py and S3 AuditLogger.
Strictly ensures NO private keys, shared secrets, session keys, or unauthenticated tokens
are ever logged.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TextIO

from qeris.s2.config import DEFAULT_AUDIT_LOG_PATH


def _redact_sensitive(obj: Any) -> Any:
    """Recursively redacts cryptographic keys, passwords, and plaintext secrets."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("key", "secret", "token", "password", "plaintext", "priv")):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = _redact_sensitive(v)
        return cleaned
    elif isinstance(obj, list):
        return [_redact_sensitive(item) for item in obj]
    elif isinstance(obj, bytes):
        return f"<bytes len={len(obj)}>"
    return obj


class GatewayAuditLogger:
    """
    Thread-safe structured audit logger emitting standardized JSON Lines.
    """

    def __init__(self, log_path: str = DEFAULT_AUDIT_LOG_PATH, sink: Optional[TextIO] = None):
        self.log_path = log_path
        self._sink = sink
        self._lock = threading.Lock()
        if self._sink is None:
            Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: str,
        *,
        device_id: str,
        flow_id: str,
        decision: str,
        reason: str,
        sensitivity: Optional[str] = None,
        security_profile: Optional[str] = None,
        mode: Optional[str] = None,
        policy_version: Optional[int] = None,
        policy_digest: Optional[str] = None,
        session_id: Optional[str] = None,
        readiness_status: Optional[str] = None,
        rate_limited: bool = False,
        cloud_status: Optional[str] = None,
        baseline_mode: Optional[str] = None,
        run_id: Optional[str] = None,
        scenario: Optional[str] = None,
        floor_violation: Optional[bool] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Constructs and writes a redacted, structured audit log entry.
        """
        now = time.time()
        record: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "ts": int(now * 1000),  # millisecond epoch (S4 schema)
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id or "default_run",
            "scenario": scenario or "default_scenario",
            "baseline_mode": baseline_mode,
            "event_type": event_type,
            "device_id": device_id,
            "flow_id": flow_id,
            "sensitivity": sensitivity,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "security_profile": security_profile,
            "mode": mode,
            "decision": decision,
            "reason": reason,
            "floor_violation": floor_violation if floor_violation is not None else False,
            "session_id": session_id,
            "readiness_status": readiness_status,
            "rate_limited": rate_limited,
            "cloud_status": cloud_status,
            "details": _redact_sensitive(details or {}),
        }

        # Format as compact, single-line JSON
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)

        with self._lock:
            if self._sink is not None:
                self._sink.write(line + "\n")
                if hasattr(self._sink, "flush"):
                    self._sink.flush()
            else:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")

        return record

    def read_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Reads recent audit logs from file."""
        if not Path(self.log_path).exists():
            return []
        lines = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except Exception:
                        pass
        return lines[-limit:]
