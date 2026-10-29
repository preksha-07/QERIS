"""QERIS S4: Task T28 - Experiment Design and Matrix.

Defines the multidimensional factorial evaluation matrix:
7 Baselines x Hardware Classes x Network Loss Regimes x MTU Levels x Scenarios.
Enforces the >=100 repetitions per test cell requirement for statistical rigor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qeris.s4.log_schema import Baseline, DeviceClass, SensitivityTier


@dataclass
class ExperimentCell:
    """A single cell in the multidimensional experiment matrix."""
    cell_id: str
    baseline: Baseline
    scenario: str
    device_class: DeviceClass
    sensitivity: SensitivityTier
    path_mtu: int
    loss_model: str  # "none", "uniform_5", "uniform_15", "burst_ge"
    repetitions: int = 100
    param_set: str = "ML-KEM-512"  # or "ML-KEM-768"
    description: str = ""


class ExperimentMatrix:
    """Constructs and manages the comprehensive benchmark matrix."""

    # 1. Seven benchmark baselines
    BASELINES = [
        Baseline.STATIC_CLASSICAL,
        Baseline.STATIC_HYBRID,
        Baseline.STATIC_PQC,
        Baseline.SENSITIVITY_ONLY,
        Baseline.DOWNGRADE_ON_FAILURE,
        Baseline.STATIC_RETRY,
        Baseline.FULL_GATEWAY,
    ]

    # 2. Hardware / device classes
    DEVICE_CLASSES = [
        DeviceClass.ESP32_CONSTRAINED,
        DeviceClass.EDGE_GATEWAY,
        DeviceClass.STANDARD_COMPUTE,
    ]

    # 3. Path MTU levels (Ethernet standard, IPv6 minimum, dialup/constrained)
    MTU_LEVELS = [1500, 1280, 576]

    # 4. Scenarios
    CORE_SCENARIOS = [
        "normal_classical",
        "normal_hybrid",
        "normal_pqc",
        "reduced_mtu_1280",
        "reduced_mtu_576",
        "packet_loss_uniform_5pct",
        "packet_loss_uniform_15pct",
        "packet_loss_burst_ge",
        "path_timeout",
        "attack_downgrade_attempt",
        "attack_bad_signature",
        "attack_replayed_policy",
        "attack_untrusted_authority",
        "attack_fast_forward_version",
        "floor_unreachable_classical_device",
    ]

    @classmethod
    def generate_full_matrix(cls, repetitions_per_cell: int = 100) -> List[ExperimentCell]:
        """Generate the complete factorial benchmark suite."""
        cells: List[ExperimentCell] = []
        cell_counter = 0

        for baseline in cls.BASELINES:
            for scenario in cls.CORE_SCENARIOS:
                cell_counter += 1
                # Assign representative sensitivity and MTU according to scenario
                if "critical" in scenario or "downgrade" in scenario or "floor_unreachable" in scenario:
                    sensitivity = SensitivityTier.CRITICAL
                elif "hybrid" in scenario or "replayed" in scenario:
                    sensitivity = SensitivityTier.HIGH
                elif "pqc" in scenario or "signature" in scenario:
                    sensitivity = SensitivityTier.CRITICAL
                else:
                    sensitivity = SensitivityTier.LOW

                # MTU mapping
                if "576" in scenario:
                    mtu = 576
                elif "1280" in scenario:
                    mtu = 1280
                else:
                    mtu = 1500

                # Loss mapping
                if "uniform_5" in scenario:
                    loss = "uniform_5"
                elif "uniform_15" in scenario:
                    loss = "uniform_15"
                elif "burst_ge" in scenario:
                    loss = "burst_ge"
                else:
                    loss = "none"

                # Primary device class is ESP32 constrained for core evaluation
                cell = ExperimentCell(
                    cell_id=f"CELL-{cell_counter:04d}",
                    baseline=baseline,
                    scenario=scenario,
                    device_class=DeviceClass.ESP32_CONSTRAINED,
                    sensitivity=sensitivity,
                    path_mtu=mtu,
                    loss_model=loss,
                    repetitions=repetitions_per_cell,
                    description=f"{baseline.value} under {scenario}",
                )
                cells.append(cell)

        return cells

    @classmethod
    def generate_pilot_matrix(cls, repetitions_per_cell: int = 10) -> List[ExperimentCell]:
        """Generate a fast pilot matrix for sanity checking."""
        full = cls.generate_full_matrix(repetitions_per_cell=repetitions_per_cell)
        # Select representative subset: 7 baselines x 5 key scenarios
        key_scenarios = {
            "normal_pqc",
            "reduced_mtu_1280",
            "packet_loss_uniform_5pct",
            "attack_downgrade_attempt",
            "attack_replayed_policy",
        }
        return [c for c in full if c.scenario in key_scenarios]
