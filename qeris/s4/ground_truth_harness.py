"""QERIS S4: Task T31 - Ground-Truth Cause-Labelling Harness.

Stamps every injected fault with its ground-truth cause class and provides
comparative tools to evaluate the S3 failure classifier's accuracy against
ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GroundTruthLabel:
    scenario_id: str
    injected_cause: str  # "security_failure", "mtu_fragment", "loss_timeout", "none"
    attack_vector: Optional[str] = None
    expected_outcome: str = "REJECT"  # "SUCCESS", "REJECT", "RETRY"


class GroundTruthHarness:
    """Manages ground-truth scenario definitions and validation against classifier output."""

    # Canonical scenario to injected cause mapping
    SCENARIO_GROUND_TRUTH: Dict[str, GroundTruthLabel] = {
        # Normal scenarios
        "normal_classical": GroundTruthLabel("normal_classical", "none", None, "SUCCESS"),
        "normal_hybrid": GroundTruthLabel("normal_hybrid", "none", None, "SUCCESS"),
        "normal_pqc": GroundTruthLabel("normal_pqc", "none", None, "SUCCESS"),

        # Network transport faults
        "packet_loss_uniform_5pct": GroundTruthLabel("packet_loss_uniform_5pct", "loss_timeout", "uniform_loss_5", "RETRY"),
        "packet_loss_uniform_15pct": GroundTruthLabel("packet_loss_uniform_15pct", "loss_timeout", "uniform_loss_15", "RETRY"),
        "packet_loss_burst_ge": GroundTruthLabel("packet_loss_burst_ge", "loss_timeout", "burst_gilbert_elliott", "RETRY"),
        "path_timeout": GroundTruthLabel("path_timeout", "loss_timeout", "excessive_delay", "RETRY"),

        # MTU / Fragmentation faults
        "reduced_mtu_1280": GroundTruthLabel("reduced_mtu_1280", "mtu_fragment", "ipv6_min_mtu", "RETRY"),
        "reduced_mtu_576": GroundTruthLabel("reduced_mtu_576", "mtu_fragment", "dialup_mtu", "RETRY"),

        # Security attacks (Threat Model T1, S3 Invariants)
        "attack_bad_signature": GroundTruthLabel("attack_bad_signature", "security_failure", "corrupted_sig", "REJECT"),
        "attack_replayed_policy": GroundTruthLabel("attack_replayed_policy", "security_failure", "stale_policy_version", "REJECT"),
        "attack_downgrade_attempt": GroundTruthLabel("attack_downgrade_attempt", "security_failure", "mode_below_floor", "REJECT"),
        "attack_untrusted_authority": GroundTruthLabel("attack_untrusted_authority", "security_failure", "untrusted_issuer", "REJECT"),
        "attack_fast_forward_version": GroundTruthLabel("attack_fast_forward_version", "security_failure", "version_jump_overflow", "REJECT"),
        "attack_fake_handshake": GroundTruthLabel("attack_fake_handshake", "security_failure", "unregistered_device", "REJECT"),
    }

    @classmethod
    def get_ground_truth(cls, scenario: str) -> GroundTruthLabel:
        return cls.SCENARIO_GROUND_TRUTH.get(
            scenario,
            GroundTruthLabel(scenario, "none", None, "UNKNOWN")
        )

    @staticmethod
    def match_prediction(injected_cause: str, classified_label: str) -> bool:
        """Evaluate if classifier prediction matches injected ground truth."""
        # Normalize representations
        injected = (injected_cause or "none").lower()
        predicted = (classified_label or "none").lower()

        # Handle enums and prefixes
        if "security" in injected:
            return "security" in predicted
        if "mtu" in injected or "fragment" in injected:
            return "mtu" in predicted or "fragment" in predicted
        if "loss" in injected or "timeout" in injected:
            return "loss" in predicted or "timeout" in predicted
        if injected in ("none", "clean"):
            return predicted in ("none", "clean", "")

        return injected == predicted
