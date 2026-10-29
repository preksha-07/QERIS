"""QERIS S4: Task T22a - Log Schema and Event Taxonomy.

Defines the canonical experiment log schema and validation rules for all
QERIS components (S1 device, S2 gateway, S3 security logic, S4 evaluations).

Schema specification (S4 Add-on §A):
  ts             : UTC timestamp in milliseconds (int)
  run_id         : Unique experiment identifier (str)
  scenario       : Benchmark scenario name (str)
  baseline       : Baseline strategy or full gateway (str)
  device_id      : Device identifier (str)
  device_class   : Hardware/resource profile (str)
  flow_id        : Flow identifier (str)
  sensitivity    : Sensitivity tier ("LOW", "MEDIUM", "HIGH", "CRITICAL")
  event          : Handshake/session event name (str)
  mode           : Cryptographic mode ("CLASSICAL", "HYBRID", "PQC", "NONE")
  cause_label    : Classifier-assigned cause ("security_failure", "mtu_fragment", "loss_timeout", "none")
  cause_injected : Ground-truth injected fault ("security_failure", "mtu_fragment", "loss_timeout", "none")
  size_bytes     : Transferred wire/payload size in bytes (int)
  duration_ms    : Elapsed handshake/operation time in milliseconds (float)
  cpu_pct        : Emulated or measured CPU utilization percentage (float)
  mem_mb         : Emulated or measured memory usage in MB (float)
  outcome        : Execution outcome ("SUCCESS", "REJECT", "TIMEOUT", "FLOOR_VIOLATION", "FLOOR_UNREACHABLE")
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional, Union


class LogEvent(str, Enum):
    CONNECTION_START   = "connection_start"
    HANDSHAKE_COMPLETE = "handshake_complete"
    DATA_SENT          = "data_sent"
    FAILURE            = "failure"
    RETRY              = "retry"
    POLICY_REJECTED    = "policy_rejected"
    REPLAY_DETECTED    = "replay_detected"
    DOWNGRADE_BLOCKED  = "downgrade_blocked"
    QUARANTINE         = "quarantine"
    REFRAGMENT         = "refragment"


class LogOutcome(str, Enum):
    SUCCESS            = "SUCCESS"
    REJECT             = "REJECT"
    TIMEOUT            = "TIMEOUT"
    FLOOR_VIOLATION    = "FLOOR_VIOLATION"
    FLOOR_UNREACHABLE  = "FLOOR_UNREACHABLE"
    QUARANTINED        = "QUARANTINED"


class Baseline(str, Enum):
    STATIC_CLASSICAL     = "static_classical"
    STATIC_HYBRID        = "static_hybrid"
    STATIC_PQC           = "static_pqc"
    SENSITIVITY_ONLY     = "sensitivity_only"
    DOWNGRADE_ON_FAILURE = "downgrade_on_failure"
    STATIC_RETRY         = "static_retry_with_floor"
    FULL_GATEWAY         = "full_gateway"


class DeviceClass(str, Enum):
    ESP32_CONSTRAINED = "esp32_constrained"  # Emulated or calibrated ESP32
    EDGE_GATEWAY      = "edge_gateway"       # Raspberry Pi / Edge Class
    STANDARD_COMPUTE  = "standard_compute"   # Standard Linux Edge Node


class SensitivityTier(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class CryptoMode(str, Enum):
    CLASSICAL = "CLASSICAL"
    HYBRID    = "HYBRID"
    PQC       = "PQC"
    NONE      = "NONE"


@dataclass
class LogRecord:
    """Canonical QERIS evaluation log entry."""
    ts: int
    run_id: str
    scenario: str
    baseline: str
    device_id: str
    device_class: str
    flow_id: str
    sensitivity: str
    event: str
    mode: str
    cause_label: str
    cause_injected: str
    size_bytes: int
    duration_ms: float
    cpu_pct: float
    mem_mb: float
    outcome: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogRecord:
        # Validate and cast fields
        return cls(
            ts=int(data["ts"]),
            run_id=str(data["run_id"]),
            scenario=str(data["scenario"]),
            baseline=str(data["baseline"]),
            device_id=str(data["device_id"]),
            device_class=str(data["device_class"]),
            flow_id=str(data["flow_id"]),
            sensitivity=str(data["sensitivity"]),
            event=str(data["event"]),
            mode=str(data["mode"]),
            cause_label=str(data["cause_label"]),
            cause_injected=str(data["cause_injected"]),
            size_bytes=int(data["size_bytes"]),
            duration_ms=float(data["duration_ms"]),
            cpu_pct=float(data["cpu_pct"]),
            mem_mb=float(data["mem_mb"]),
            outcome=str(data["outcome"]),
        )

    @classmethod
    def from_json(cls, line: str) -> LogRecord:
        data = json.loads(line)
        return cls.from_dict(data)


def create_log_record(
    run_id: str,
    scenario: str,
    baseline: Union[Baseline, str],
    device_id: str,
    device_class: Union[DeviceClass, str],
    flow_id: str,
    sensitivity: Union[SensitivityTier, str],
    event: Union[LogEvent, str],
    mode: Union[CryptoMode, str],
    cause_label: str = "none",
    cause_injected: str = "none",
    size_bytes: int = 0,
    duration_ms: float = 0.0,
    cpu_pct: float = 0.0,
    mem_mb: float = 0.0,
    outcome: Union[LogOutcome, str] = LogOutcome.SUCCESS,
    ts: Optional[int] = None,
) -> LogRecord:
    """Helper factory for generating standard LogRecord with current epoch ms."""
    current_ts = ts if ts is not None else int(time.time() * 1000)
    return LogRecord(
        ts=current_ts,
        run_id=str(run_id),
        scenario=str(scenario),
        baseline=baseline.value if isinstance(baseline, Baseline) else str(baseline),
        device_id=str(device_id),
        device_class=device_class.value if isinstance(device_class, DeviceClass) else str(device_class),
        flow_id=str(flow_id),
        sensitivity=sensitivity.value if isinstance(sensitivity, SensitivityTier) else str(sensitivity),
        event=event.value if isinstance(event, LogEvent) else str(event),
        mode=mode.value if isinstance(mode, CryptoMode) else str(mode),
        cause_label=str(cause_label),
        cause_injected=str(cause_injected),
        size_bytes=int(size_bytes),
        duration_ms=float(duration_ms),
        cpu_pct=float(cpu_pct),
        mem_mb=float(mem_mb),
        outcome=outcome.value if isinstance(outcome, LogOutcome) else str(outcome),
    )
