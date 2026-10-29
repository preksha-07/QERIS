"""QERIS S4: Task T21 - Network Fault Injection and Emulation Engine.

Implements two complementary fault-injection modalities:
1. System-level Linux Traffic Control (tc-netem) configuration generator and
   executor for testbed environments with root privileges.
2. In-process deterministic software network fault simulator with Gilbert-Elliott
   burst loss, uniform loss, path MTU truncation, and delay modeling.

This ensures reproducible fault injection on both live network testbeds and
in-process simulation harnesses (as required by S4 Spec §B & §9).
"""
from __future__ import annotations

import random
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class FaultType(str, Enum):
    NONE               = "none"
    UNIFORM_LOSS       = "uniform_loss"
    BURST_LOSS         = "burst_loss"
    REDUCED_MTU        = "reduced_mtu"
    DELAY_TIMEOUT      = "delay_timeout"
    REORDER            = "reorder"
    DUPLICATE          = "duplicate"
    SECURITY_INJECTION = "security_injection"


@dataclass
class GilbertElliottParams:
    """Gilbert-Elliott two-state Markov model parameters.

    States:
      Good (G): low loss probability (1 - h)
      Bad  (B): high loss probability (1 - k)
    Transitions:
      p: probability of transition G -> B
      r: probability of transition B -> G
    """
    p: float = 0.05   # G -> B
    r: float = 0.40   # B -> G
    loss_prob_g: float = 0.01  # (1 - h)
    loss_prob_b: float = 0.90  # (1 - k)


class NetemController:
    """Linux tc-netem command builder and runner."""

    def __init__(self, interface: str = "eth0"):
        self.interface = interface

    def cmd_clean(self) -> str:
        return f"tc qdisc del dev {self.interface} root 2>/dev/null || true"

    def cmd_uniform_loss(self, percent: float) -> str:
        return f"tc qdisc add dev {self.interface} root netem loss {percent:.1f}%"

    def cmd_burst_loss(self, params: GilbertElliottParams) -> str:
        p_pct = params.p * 100.0
        r_pct = params.r * 100.0
        h_pct = (1.0 - params.loss_prob_g) * 100.0
        k_pct = (1.0 - params.loss_prob_b) * 100.0
        return (
            f"tc qdisc add dev {self.interface} root netem loss gemodel "
            f"{p_pct:.1f}% {r_pct:.1f}% {h_pct:.1f}% {k_pct:.1f}%"
        )

    def cmd_delay_jitter(self, delay_ms: int, jitter_ms: int) -> str:
        return f"tc qdisc add dev {self.interface} root netem delay {delay_ms}ms {jitter_ms}ms"

    def cmd_reorder(self, delay_ms: int, percent: float, correlation: float = 50.0) -> str:
        return f"tc qdisc add dev {self.interface} root netem delay {delay_ms}ms reorder {percent:.1f}% {correlation:.1f}%"

    def cmd_duplicate(self, percent: float) -> str:
        return f"tc qdisc add dev {self.interface} root netem duplicate {percent:.1f}%"

    def cmd_set_mtu(self, mtu: int) -> str:
        return f"ip link set dev {self.interface} mtu {mtu}"

    def apply_shell(self, cmd: str) -> Tuple[int, str]:
        """Execute netem shell command if permissions allow."""
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return res.returncode, res.stdout + res.stderr
        except Exception as e:
            return -1, str(e)


class SoftwareFaultSimulator:
    """Deterministic, seedable in-process fault injector.

    Simulates network layer effects:
    - MTU fragmentation boundary checks: drops or fragments packets based on path MTU.
    - Loss models: Uniform independent random or Gilbert-Elliott burst loss.
    - Latency and timeouts.
    - Security faults injection.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        path_mtu: int = 1500,
        loss_model: FaultType = FaultType.NONE,
        uniform_loss_rate: float = 0.0,
        ge_params: Optional[GilbertElliottParams] = None,
        timeout_budget_ms: float = 1000.0,
    ):
        self.rng = random.Random(seed)
        self.path_mtu = path_mtu
        self.loss_model = loss_model
        self.uniform_loss_rate = uniform_loss_rate
        self.ge_params = ge_params or GilbertElliottParams()
        self.timeout_budget_ms = timeout_budget_ms

        # Gilbert-Elliott state: 0 = Good, 1 = Bad
        self._ge_state = 0

    def set_seed(self, seed: int) -> None:
        self.rng.seed(seed)
        self._ge_state = 0

    def evaluate_transmission(
        self,
        packet_size: int,
        fragment_size: Optional[int] = None,
        simulated_delay_ms: float = 20.0,
        is_security_attack: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate whether a transmission succeeds or what failure occurs.

        Returns dict with:
          success: bool
          cause: str ("none", "security_failure", "mtu_fragment", "loss_timeout")
          fragment_count: int
          effective_delay_ms: float
        """
        if is_security_attack:
            return {
                "success": False,
                "cause": "security_failure",
                "fragment_count": 1,
                "effective_delay_ms": simulated_delay_ms,
            }

        effective_frag_size = fragment_size or packet_size
        effective_mtu = self.path_mtu

        # Check MTU violation: if packet exceeds path MTU without proper fragmentation
        if effective_frag_size > effective_mtu:
            return {
                "success": False,
                "cause": "mtu_fragment",
                "fragment_count": max(1, (packet_size + effective_frag_size - 1) // effective_frag_size),
                "effective_delay_ms": simulated_delay_ms,
            }

        num_fragments = max(1, (packet_size + effective_frag_size - 1) // effective_frag_size)

        # Timeout check
        if simulated_delay_ms >= self.timeout_budget_ms:
            return {
                "success": False,
                "cause": "loss_timeout",
                "fragment_count": num_fragments,
                "effective_delay_ms": simulated_delay_ms,
            }

        # Loss check per fragment
        for _ in range(num_fragments):
            if self._is_fragment_dropped():
                return {
                    "success": False,
                    "cause": "loss_timeout",
                    "fragment_count": num_fragments,
                    "effective_delay_ms": simulated_delay_ms,
                }

        return {
            "success": True,
            "cause": "none",
            "fragment_count": num_fragments,
            "effective_delay_ms": simulated_delay_ms,
        }

    def _is_fragment_dropped(self) -> bool:
        """Evaluate loss according to current loss model."""
        if self.loss_model == FaultType.NONE:
            return False

        if self.loss_model == FaultType.UNIFORM_LOSS:
            return self.rng.random() < self.uniform_loss_rate

        if self.loss_model == FaultType.BURST_LOSS:
            # Update Gilbert-Elliott Markov state
            if self._ge_state == 0:  # Good
                if self.rng.random() < self.ge_params.p:
                    self._ge_state = 1
            else:  # Bad
                if self.rng.random() < self.ge_params.r:
                    self._ge_state = 0

            loss_prob = self.ge_params.loss_prob_b if self._ge_state == 1 else self.ge_params.loss_prob_g
            return self.rng.random() < loss_prob

        return False
