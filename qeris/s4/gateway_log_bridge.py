"""
QERIS S4 Gateway Log Bridge  (Stage 5 Integration)
====================================================
Converts QERIS gateway audit log entries (produced by qeris/s2/gateway.py)
into canonical S4 LogRecord objects for the analysis and evaluation pipeline.

Gateway logs can come in two formats:
  - Legacy (pre-Phase-4): {timestamp, flow_id, requested_mode, decision, reason}
  - Current (Phase-4+):   {trace_id, ts, timestamp, device_id, flow_id,
                           sensitivity, minimum_mode, requested_mode,
                           policy_version, authority_id, decision, reason,
                           s3_verdict, cause_label, security_reason, crypto_status}

Both formats are accepted; missing fields use safe defaults.

Usage
-----
    from qeris.s4.gateway_log_bridge import GatewayLogBridge, BridgeConfig

    bridge = GatewayLogBridge()
    table = bridge.ingest_file("qeris/s2/gateway_logs.jsonl")
    print(len(table), "records ingested")

    # Analyse with existing S4 tools
    from qeris.s4.analysis import summarize_baselines
    summary = summarize_baselines(table)
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from qeris.s4.log_parser import LogTable
from qeris.s4.log_schema import (
    Baseline,
    CryptoMode,
    DeviceClass,
    LogEvent,
    LogOutcome,
    LogRecord,
    SensitivityTier,
    create_log_record,
)


# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

# Gateway decision → S4 LogOutcome
_DECISION_TO_OUTCOME: dict[str, str] = {
    "ALLOW": LogOutcome.SUCCESS.value,
    "REJECT": LogOutcome.REJECT.value,
    "FLOOR_UNREACHABLE": LogOutcome.FLOOR_UNREACHABLE.value,
}

# crypto_status → S4 LogEvent
_CRYPTO_STATUS_TO_EVENT: dict[str, str] = {
    "VERIFIED_ROUNDTRIP": LogEvent.HANDSHAKE_COMPLETE.value,
    "REJECTED_BEFORE_SESSION": LogEvent.FAILURE.value,
    "UNSUPPORTED_MODE": LogEvent.FAILURE.value,
    "SKIPPED": LogEvent.CONNECTION_START.value,
    "ERROR": LogEvent.FAILURE.value,
    "TAMPERING_DETECTED": LogEvent.FAILURE.value,
}

# s3_verdict keywords → S4 LogEvent
_VERDICT_TO_EVENT: dict[str, str] = {
    "RETRY": LogEvent.RETRY.value,
    "DISCARD_AND_LOG": LogEvent.FAILURE.value,
    "QUARANTINED": LogEvent.QUARANTINE.value,
    "FLOOR_UNREACHABLE": LogEvent.FAILURE.value,
    "SUCCESS": LogEvent.HANDSHAKE_COMPLETE.value,
    "NONE": LogEvent.CONNECTION_START.value,
}

# Sensitivity string → S4 SensitivityTier
_SENSITIVITY_MAP: dict[str, str] = {
    "LOW": SensitivityTier.LOW.value,
    "MEDIUM": SensitivityTier.MEDIUM.value,
    "HIGH": SensitivityTier.HIGH.value,
    "CRITICAL": SensitivityTier.CRITICAL.value,
}

# Crypto mode string → S4 CryptoMode
_MODE_MAP: dict[str, str] = {
    "PQC": CryptoMode.PQC.value,
    "PQ": CryptoMode.PQC.value,
    "HYBRID": CryptoMode.HYBRID.value,
    "CLASSICAL": CryptoMode.CLASSICAL.value,
    "NONE": CryptoMode.NONE.value,
}


# ---------------------------------------------------------------------------
# Bridge configuration
# ---------------------------------------------------------------------------

@dataclass
class BridgeConfig:
    """Configuration for gateway→S4 mapping decisions."""
    run_id: str = "gateway_live"
    scenario: str = "live_gateway"
    baseline: str = Baseline.FULL_GATEWAY.value
    device_class: str = DeviceClass.EDGE_GATEWAY.value
    # How to handle S4-only fields absent from gateway logs
    default_size_bytes: int = 0
    default_duration_ms: float = 0.0
    default_cpu_pct: float = 0.0
    default_mem_mb: float = 0.0
    skip_legacy_entries: bool = False   # If True, skip pre-Phase-4 entries missing device_id


# ---------------------------------------------------------------------------
# Bridge core
# ---------------------------------------------------------------------------

class GatewayLogBridge:
    """Converts gateway audit log JSONL entries into S4 canonical LogRecords.

    Accepts both legacy (5-field) and current (17-field) gateway log formats.
    Entries missing required S4 fields are given safe defaults and flagged
    in their scenario field as 'legacy_entry'.
    """

    def __init__(self, config: Optional[BridgeConfig] = None):
        self.config = config or BridgeConfig()

    # ------------------------------------------------------------------ public

    def ingest_file(
        self,
        log_path: Union[str, Path],
        skip_errors: bool = True,
    ) -> LogTable:
        """Parse a gateway JSONL log file and return a LogTable of S4 LogRecords."""
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(f"Gateway log file not found: {path}")

        table = LogTable()
        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = json.loads(line)
                    record = self._convert_entry(entry)
                    if record is not None:
                        table.append(record)
                except Exception as err:
                    if not skip_errors:
                        raise ValueError(f"Error on line {line_no} in {path}: {err}") from err
        return table

    def ingest_entries(
        self,
        entries: List[Dict[str, Any]],
    ) -> LogTable:
        """Convert a list of already-parsed gateway log dicts into a LogTable."""
        table = LogTable()
        for entry in entries:
            record = self._convert_entry(entry)
            if record is not None:
                table.append(record)
        return table

    def convert_one(self, entry: Dict[str, Any]) -> Optional[LogRecord]:
        """Convert a single gateway log entry dict to a LogRecord, or None to skip."""
        return self._convert_entry(entry)

    # ----------------------------------------------------------------- private

    def _convert_entry(self, entry: Dict[str, Any]) -> Optional[LogRecord]:
        """Map one gateway log entry to a canonical LogRecord."""
        cfg = self.config

        # --- Is this a Phase-4 entry or legacy? ---
        is_phase4 = "ts" in entry and "device_id" in entry and "cause_label" in entry
        is_legacy = not is_phase4

        if is_legacy and cfg.skip_legacy_entries:
            return None

        # --- Timestamp ---
        if is_phase4:
            ts_val = int(entry["ts"])
        else:
            # Legacy entries have ISO timestamp string; convert to epoch ms
            ts_str = entry.get("timestamp", "")
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts_val = int(dt.timestamp() * 1000)
            except Exception:
                ts_val = int(time.time() * 1000)

        # --- Core identifiers ---
        device_id = str(entry.get("device_id", "unknown"))
        flow_id = str(entry.get("flow_id", "unknown"))
        decision = str(entry.get("decision", "REJECT")).upper()
        requested_mode = str(entry.get("requested_mode", "UNKNOWN")).upper()

        # --- Sensitivity ---
        sensitivity_raw = str(entry.get("sensitivity") or "LOW").upper()
        sensitivity = _SENSITIVITY_MAP.get(sensitivity_raw, SensitivityTier.LOW.value)

        # --- Mode ---
        mode = _MODE_MAP.get(requested_mode, CryptoMode.NONE.value)

        # --- Outcome ---
        outcome = _DECISION_TO_OUTCOME.get(decision, LogOutcome.REJECT.value)

        # --- Cause label ---
        if is_phase4:
            cause_label = str(entry.get("cause_label", "none"))
        else:
            # Infer from legacy reason string
            cause_label = _infer_cause_label_from_reason(
                str(entry.get("reason", "")),
                decision,
            )

        # --- Event ---
        if is_phase4:
            crypto_status = str(entry.get("crypto_status", "SKIPPED")).upper()
            s3_verdict = str(entry.get("s3_verdict", "NONE")).upper()
            event = _CRYPTO_STATUS_TO_EVENT.get(
                crypto_status,
                _VERDICT_TO_EVENT.get(s3_verdict, LogEvent.CONNECTION_START.value)
            )
        else:
            event = LogEvent.FAILURE.value if decision == "REJECT" else LogEvent.HANDSHAKE_COMPLETE.value

        # --- Scenario ---
        if is_legacy:
            scenario = "legacy_entry"
        else:
            scenario = cfg.scenario

        # --- Run ID ---
        run_id = cfg.run_id
        trace_id = entry.get("trace_id", "")
        if trace_id:
            run_id = f"{cfg.run_id}:{trace_id}"

        return LogRecord(
            ts=ts_val,
            run_id=run_id,
            scenario=scenario,
            baseline=cfg.baseline,
            device_id=device_id,
            device_class=cfg.device_class,
            flow_id=flow_id,
            sensitivity=sensitivity,
            event=event,
            mode=mode,
            cause_label=cause_label,
            cause_injected="none",  # Live gateway entries have no injected fault
            size_bytes=cfg.default_size_bytes,
            duration_ms=cfg.default_duration_ms,
            cpu_pct=cfg.default_cpu_pct,
            mem_mb=cfg.default_mem_mb,
            outcome=outcome,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_cause_label_from_reason(reason: str, decision: str) -> str:
    """Heuristic cause label inference for legacy log entries without cause_label."""
    if decision == "ALLOW":
        return "none"
    reason_lc = reason.lower()
    if any(kw in reason_lc for kw in ("signature", "policy", "authority", "algorithm", "floor", "mode", "downgrade")):
        return "security_failure"
    if any(kw in reason_lc for kw in ("mtu", "fragment", "size")):
        return "mtu_fragment"
    if any(kw in reason_lc for kw in ("timeout", "loss", "no response", "retry")):
        return "loss_timeout"
    return "loss_timeout"  # conservative default for unclassified rejects
