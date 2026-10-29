"""QERIS S4: Tasks T23a, T23b & T29 - Baseline Execution Engine.

Implements all 7 comparative baselines and the full QERIS gateway strategy:
1. Static Classical
2. Static Hybrid
3. Static PQC
4. Sensitivity-Only (no cause-aware recovery)
5. Downgrade-on-Failure (naive industry fallback that violates security floors)
6. Static Retry with Floor (blind retries without cause classification)
7. Full Gateway (QERIS cause-classified, security-floor-bounded recovery)

Each baseline is executable under identical network and fault conditions.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from qeris.s4.fault_injection import FaultType, SoftwareFaultSimulator
from qeris.s4.ground_truth_harness import GroundTruthHarness
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

# Reference calibrations for ESP32 and edge platforms
HARDWARE_CALIBRATION = {
    DeviceClass.ESP32_CONSTRAINED: {
        "CLASSICAL": {"duration_base_ms": 18.5, "duration_std": 2.1, "cpu_pct": 28.0, "mem_mb": 0.08},
        "HYBRID":    {"duration_base_ms": 46.2, "duration_std": 4.5, "cpu_pct": 52.0, "mem_mb": 0.14},
        "PQC":       {"duration_base_ms": 94.8, "duration_std": 8.0, "cpu_pct": 84.0, "mem_mb": 0.22},
    },
    DeviceClass.EDGE_GATEWAY: {
        "CLASSICAL": {"duration_base_ms": 5.2,  "duration_std": 0.6, "cpu_pct": 8.0,  "mem_mb": 1.2},
        "HYBRID":    {"duration_base_ms": 12.1, "duration_std": 1.1, "cpu_pct": 18.0, "mem_mb": 2.1},
        "PQC":       {"duration_base_ms": 22.4, "duration_std": 2.0, "cpu_pct": 34.0, "mem_mb": 3.8},
    },
    DeviceClass.STANDARD_COMPUTE: {
        "CLASSICAL": {"duration_base_ms": 1.4,  "duration_std": 0.2, "cpu_pct": 2.0,  "mem_mb": 2.5},
        "HYBRID":    {"duration_base_ms": 3.5,  "duration_std": 0.4, "cpu_pct": 5.0,  "mem_mb": 4.0},
        "PQC":       {"duration_base_ms": 6.8,  "duration_std": 0.7, "cpu_pct": 11.0, "mem_mb": 6.5},
    },
}

WIRE_SIZES = {
    "CLASSICAL": 240,    # ClientHello + ServerHello + Finished (ECDH)
    "HYBRID":    1150,   # X25519 + ML-KEM-512 public keys + ciphertext
    "PQC":       1820,   # ML-KEM-512 KEM encapsulation + certificate/sig
}

MINIMUM_FLOOR_MAP = {
    SensitivityTier.LOW:      CryptoMode.CLASSICAL,
    SensitivityTier.MEDIUM:   CryptoMode.HYBRID,
    SensitivityTier.HIGH:     CryptoMode.HYBRID,
    SensitivityTier.CRITICAL: CryptoMode.PQC,
}

MODE_SECURITY_RANK = {
    CryptoMode.CLASSICAL: 1,
    CryptoMode.HYBRID:    2,
    CryptoMode.PQC:       3,
    CryptoMode.NONE:      0,
}


@dataclass
class HandshakeResult:
    outcome: LogOutcome
    mode: CryptoMode
    cause_injected: str
    cause_label: str
    duration_ms: float
    size_bytes: int
    cpu_pct: float
    mem_mb: float
    retransmissions: int
    floor_violation: bool
    details: str = ""


class BaselineEngine:
    """Simulates a handshake execution for any given baseline and scenario."""

    def __init__(self, fault_simulator: SoftwareFaultSimulator, seed: int = 42):
        self.fault_sim = fault_simulator
        self.rng = random.Random(seed)

    def execute_handshake(
        self,
        baseline: Baseline,
        scenario: str,
        device_class: DeviceClass,
        sensitivity: SensitivityTier,
        device_supported_modes: Optional[list[CryptoMode]] = None,
        max_retries: int = 3,
    ) -> HandshakeResult:
        """Run a single handshake trial under the baseline's strategy."""
        gt = GroundTruthHarness.get_ground_truth(scenario)
        cause_injected = gt.injected_cause
        is_attack = "attack" in scenario
        is_unreachable = "floor_unreachable" in scenario

        supported = device_supported_modes or [CryptoMode.CLASSICAL, CryptoMode.HYBRID, CryptoMode.PQC]
        minimum_floor = MINIMUM_FLOOR_MAP[sensitivity]
        floor_rank = MODE_SECURITY_RANK[minimum_floor]

        # 1. Classical-only device on Critical flow check
        if is_unreachable or (max(MODE_SECURITY_RANK[m] for m in supported) < floor_rank):
            return HandshakeResult(
                outcome=LogOutcome.FLOOR_UNREACHABLE,
                mode=CryptoMode.NONE,
                cause_injected="security_failure" if is_attack else "none",
                cause_label="security_failure",
                duration_ms=2.0,
                size_bytes=64,
                cpu_pct=5.0,
                mem_mb=0.05,
                retransmissions=0,
                floor_violation=False,
                details="Device maximum capability cannot satisfy signed security floor",
            )

        # 2. Select initial requested mode based on baseline
        if baseline == Baseline.STATIC_CLASSICAL:
            mode = CryptoMode.CLASSICAL
        elif baseline == Baseline.STATIC_HYBRID:
            mode = CryptoMode.HYBRID
        elif baseline == Baseline.STATIC_PQC:
            mode = CryptoMode.PQC
        else:
            # Full Gateway, Sensitivity-Only, Downgrade-on-Failure, Static Retry
            # start at the floor or highest available
            mode = minimum_floor

        # Baseline specific checks against floor
        if baseline in (Baseline.STATIC_CLASSICAL, Baseline.STATIC_HYBRID):
            if MODE_SECURITY_RANK[mode] < floor_rank:
                # Static baseline cannot meet floor: rejected
                return HandshakeResult(
                    outcome=LogOutcome.REJECT,
                    mode=mode,
                    cause_injected="security_failure" if is_attack else "none",
                    cause_label="security_failure",
                    duration_ms=3.0,
                    size_bytes=120,
                    cpu_pct=6.0,
                    mem_mb=0.05,
                    retransmissions=0,
                    floor_violation=False,
                    details="Static mode is below required security floor",
                )

        # 3. Simulate transmission and recovery loops
        retransmissions = 0
        current_mode = mode
        packet_size = WIRE_SIZES[current_mode.value]
        fragment_size = packet_size  # initial unfragmented

        # Hardware profiling
        hw = HARDWARE_CALIBRATION[device_class][current_mode.value]
        base_dur = max(1.0, self.rng.gauss(hw["duration_base_ms"], hw["duration_std"]))

        total_bytes = packet_size
        elapsed_ms = base_dur

        # Execution loop
        while True:
            # Check attack condition first (S3 Invariant / Threat Model T1)
            if is_attack:
                # Ground truth is security_failure
                if baseline == Baseline.FULL_GATEWAY:
                    # QERIS S3 detects security failure immediately, halts and logs
                    return HandshakeResult(
                        outcome=LogOutcome.REJECT,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label="security_failure",
                        duration_ms=elapsed_ms + 4.0,
                        size_bytes=total_bytes,
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=0,
                        floor_violation=False,
                        details="QERIS S3 caught attack: invalid signature / replay / downgrade blocked",
                    )
                elif baseline == Baseline.STATIC_RETRY:
                    # Blindly retries security failure wasting bandwidth!
                    retransmissions += 1
                    total_bytes += packet_size
                    elapsed_ms += base_dur
                    if retransmissions >= max_retries:
                        return HandshakeResult(
                            outcome=LogOutcome.REJECT,
                            mode=current_mode,
                            cause_injected=cause_injected,
                            cause_label="loss_timeout",  # Misdiagnosed as timeout
                            duration_ms=elapsed_ms,
                            size_bytes=total_bytes,
                            cpu_pct=hw["cpu_pct"],
                            mem_mb=hw["mem_mb"],
                            retransmissions=retransmissions,
                            floor_violation=False,
                            details="Static retry exhausted after blindly retrying security failure",
                        )
                    continue
                elif baseline == Baseline.DOWNGRADE_ON_FAILURE:
                    # Downgrades upon failure! Violates floor!
                    retransmissions += 1
                    current_mode = CryptoMode.CLASSICAL
                    return HandshakeResult(
                        outcome=LogOutcome.FLOOR_VIOLATION,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label="loss_timeout",
                        duration_ms=elapsed_ms + 10.0,
                        size_bytes=total_bytes + WIRE_SIZES["CLASSICAL"],
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=retransmissions,
                        floor_violation=True,
                        details="CRITICAL: Downgraded to CLASSICAL upon attack failure!",
                    )
                else:
                    return HandshakeResult(
                        outcome=LogOutcome.REJECT,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label="security_failure",
                        duration_ms=elapsed_ms,
                        size_bytes=total_bytes,
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=0,
                        floor_violation=False,
                        details="Attack rejected by static baseline",
                    )

            # Evaluate network transmission
            net_eval = self.fault_sim.evaluate_transmission(
                packet_size=packet_size,
                fragment_size=fragment_size,
                simulated_delay_ms=base_dur,
                is_security_attack=False,
            )

            if net_eval["success"]:
                # Success!
                floor_violation = (MODE_SECURITY_RANK[current_mode] < floor_rank)
                return HandshakeResult(
                    outcome=LogOutcome.FLOOR_VIOLATION if floor_violation else LogOutcome.SUCCESS,
                    mode=current_mode,
                    cause_injected="none",
                    cause_label="none",
                    duration_ms=elapsed_ms,
                    size_bytes=total_bytes,
                    cpu_pct=hw["cpu_pct"],
                    mem_mb=hw["mem_mb"],
                    retransmissions=retransmissions,
                    floor_violation=floor_violation,
                    details="Handshake established successfully",
                )

            # Transmission failed
            failure_cause = net_eval["cause"]
            retransmissions += 1

            # Strategy actions
            if baseline == Baseline.SENSITIVITY_ONLY:
                # No recovery logic: immediately fails on network fault
                return HandshakeResult(
                    outcome=LogOutcome.TIMEOUT,
                    mode=current_mode,
                    cause_injected=cause_injected,
                    cause_label="loss_timeout",
                    duration_ms=elapsed_ms + 50.0,
                    size_bytes=total_bytes,
                    cpu_pct=hw["cpu_pct"],
                    mem_mb=hw["mem_mb"],
                    retransmissions=retransmissions,
                    floor_violation=False,
                    details="Sensitivity-Only aborted on first network failure",
                )

            elif baseline == Baseline.DOWNGRADE_ON_FAILURE:
                # Naive downgrade: step down mode to maintain connectivity
                if current_mode == CryptoMode.PQC:
                    current_mode = CryptoMode.HYBRID
                elif current_mode == CryptoMode.HYBRID:
                    current_mode = CryptoMode.CLASSICAL

                packet_size = WIRE_SIZES[current_mode.value]
                fragment_size = packet_size
                total_bytes += packet_size
                elapsed_ms += base_dur

                if MODE_SECURITY_RANK[current_mode] < floor_rank:
                    # Security floor violated!
                    return HandshakeResult(
                        outcome=LogOutcome.FLOOR_VIOLATION,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label="loss_timeout",
                        duration_ms=elapsed_ms,
                        size_bytes=total_bytes,
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=retransmissions,
                        floor_violation=True,
                        details=f"Floor violated: downgraded to {current_mode.value} below floor {minimum_floor.value}",
                    )

            elif baseline == Baseline.STATIC_RETRY:
                # Blind retry with floor: does not adapt MTU, just sends again
                total_bytes += packet_size
                elapsed_ms += base_dur
                if retransmissions >= max_retries:
                    return HandshakeResult(
                        outcome=LogOutcome.TIMEOUT,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label="loss_timeout",
                        duration_ms=elapsed_ms,
                        size_bytes=total_bytes,
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=retransmissions,
                        floor_violation=False,
                        details="Static retry exceeded maximum attempts without cause adaptation",
                    )

            elif baseline == Baseline.FULL_GATEWAY:
                # QERIS Cause-Aware, Floor-Bounded Recovery
                if failure_cause == "mtu_fragment":
                    # Cause classified as MTU: dynamically reduce fragment size!
                    # Adapts fragment size to path MTU - 64 bytes header
                    fragment_size = min(self.fault_sim.path_mtu - 64, 512)
                    total_bytes += packet_size
                    elapsed_ms += (base_dur * 1.2)  # Slight re-fragmentation overhead
                    cause_label = "mtu_fragment"

                elif failure_cause == "loss_timeout":
                    # Cause classified as Loss: exponential backoff retry at same floor
                    backoff_ms = min(200.0, 20.0 * (2 ** retransmissions))
                    elapsed_ms += (base_dur + backoff_ms)
                    total_bytes += packet_size
                    cause_label = "loss_timeout"

                if retransmissions >= max_retries:
                    return HandshakeResult(
                        outcome=LogOutcome.TIMEOUT,
                        mode=current_mode,
                        cause_injected=cause_injected,
                        cause_label=cause_label,
                        duration_ms=elapsed_ms,
                        size_bytes=total_bytes,
                        cpu_pct=hw["cpu_pct"],
                        mem_mb=hw["mem_mb"],
                        retransmissions=retransmissions,
                        floor_violation=False,
                        details="QERIS Recovery cap reached under severe network conditions",
                    )

            else:
                # Static classical / hybrid / pqc fail on network drops
                return HandshakeResult(
                    outcome=LogOutcome.TIMEOUT,
                    mode=current_mode,
                    cause_injected=cause_injected,
                    cause_label="loss_timeout",
                    duration_ms=elapsed_ms,
                    size_bytes=total_bytes,
                    cpu_pct=hw["cpu_pct"],
                    mem_mb=hw["mem_mb"],
                    retransmissions=retransmissions,
                    floor_violation=False,
                    details="Static baseline failed to transmit over impaired channel",
                )
