"""QERIS S4: Tasks T29 & T30 - Experiment Runner and Data Collection Suite.

Automates test execution across all benchmark matrix cells, applies network
fault injection, records canonical JSONL log streams with injected ground truth,
and stores immutable raw datasets under data/raw/<run_id>/.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from qeris.s4.baseline_engine import BaselineEngine
from qeris.s4.experiment_matrix import ExperimentCell, ExperimentMatrix
from qeris.s4.fault_injection import FaultType, GilbertElliottParams, SoftwareFaultSimulator
from qeris.s4.ground_truth_harness import GroundTruthHarness
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


class ExperimentRunner:
    """Orchestrates matrix execution, logging, and raw data persistence."""

    def __init__(self, output_base_dir: str = "data/raw", base_seed: int = 1337):
        self.output_base_dir = Path(output_base_dir)
        self.base_seed = base_seed

    def run_matrix(
        self,
        cells: List[ExperimentCell],
        run_id: Optional[str] = None,
        verbose: bool = True,
    ) -> Tuple[str, Path, LogTable]:
        """Execute a list of ExperimentCells and persist raw logs."""
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        active_run_id = run_id or f"run_{timestamp_str}"
        run_dir = self.output_base_dir / active_run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        raw_log_path = run_dir / "raw_events.jsonl"
        metadata_path = run_dir / "run_metadata.json"

        # Record system environment metadata
        metadata = {
            "run_id": active_run_id,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "python_version": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "total_cells": len(cells),
            "seed": self.base_seed,
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        table = LogTable()
        total_handshakes = sum(c.repetitions for c in cells)
        completed_handshakes = 0

        if verbose:
            print(f"[*] Starting QERIS Benchmark: Run ID '{active_run_id}'")
            print(f"[*] Total cells: {len(cells)}, Total handshakes: {total_handshakes}")
            print(f"[*] Raw logs will be saved to: {raw_log_path}")

        with open(raw_log_path, "w", encoding="utf-8") as log_file:
            for cell_idx, cell in enumerate(cells, start=1):
                # Configure fault simulator for cell
                loss_model = FaultType.NONE
                uniform_rate = 0.0
                if cell.loss_model == "uniform_5":
                    loss_model = FaultType.UNIFORM_LOSS
                    uniform_rate = 0.05
                elif cell.loss_model == "uniform_15":
                    loss_model = FaultType.UNIFORM_LOSS
                    uniform_rate = 0.15
                elif cell.loss_model == "burst_ge":
                    loss_model = FaultType.BURST_LOSS

                fault_sim = SoftwareFaultSimulator(
                    seed=self.base_seed + cell_idx,
                    path_mtu=cell.path_mtu,
                    loss_model=loss_model,
                    uniform_loss_rate=uniform_rate,
                    ge_params=GilbertElliottParams(p=0.08, r=0.35, loss_prob_g=0.01, loss_prob_b=0.85),
                )

                engine = BaselineEngine(fault_sim, seed=self.base_seed + (cell_idx * 100))

                for rep in range(1, cell.repetitions + 1):
                    result = engine.execute_handshake(
                        baseline=cell.baseline,
                        scenario=cell.scenario,
                        device_class=cell.device_class,
                        sensitivity=cell.sensitivity,
                    )

                    # Determine canonical event
                    if result.outcome == LogOutcome.SUCCESS:
                        event = LogEvent.HANDSHAKE_COMPLETE
                    elif result.outcome == LogOutcome.FLOOR_VIOLATION:
                        event = LogEvent.DOWNGRADE_BLOCKED if cell.baseline == Baseline.FULL_GATEWAY else LogEvent.FAILURE
                    elif result.outcome == LogOutcome.REJECT:
                        event = LogEvent.POLICY_REJECTED
                    else:
                        event = LogEvent.FAILURE

                    record = create_log_record(
                        run_id=active_run_id,
                        scenario=cell.scenario,
                        baseline=cell.baseline,
                        device_id=f"dev_{cell.device_class.value}_01",
                        device_class=cell.device_class,
                        flow_id=f"flow_{cell.sensitivity.value.lower()}_01",
                        sensitivity=cell.sensitivity,
                        event=event,
                        mode=result.mode,
                        cause_label=result.cause_label,
                        cause_injected=result.cause_injected,
                        size_bytes=result.size_bytes,
                        duration_ms=result.duration_ms,
                        cpu_pct=result.cpu_pct,
                        mem_mb=result.mem_mb,
                        outcome=result.outcome,
                    )

                    log_file.write(record.to_json() + "\n")
                    table.append(record)
                    completed_handshakes += 1

                if verbose and (cell_idx % 15 == 0 or cell_idx == len(cells)):
                    progress_pct = (completed_handshakes / total_handshakes) * 100.0
                    print(f"    - Processed cell {cell_idx}/{len(cells)} ({progress_pct:.1f}% complete)")

        if verbose:
            print(f"[+] Run complete! Collected {len(table)} records across {len(cells)} cells.")

        return active_run_id, raw_log_path, table
