"""QERIS S4: Task T32 - Statistical Analysis and Evaluation Engine.

Provides rigorous, publication-grade statistical analytics:
1. Wilson score intervals for proportions (success rate, floor violations).
2. Non-parametric robust dispersion: Median and Interquartile Range (IQR).
3. Parametric moments: Sample Mean and Sample Standard Deviation.
4. Multiclass Confusion Matrix with per-class Precision, Recall, F1, and Support.
5. Security compliance verification (zero-floor-violation audit).
"""
from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qeris.s4.log_parser import LogTable
from qeris.s4.log_schema import Baseline, LogOutcome, LogRecord


@dataclass
class ProportionStats:
    count: int
    total: int
    proportion: float
    wilson_lower: float
    wilson_upper: float
    confidence_level: float = 0.95

    def formatted(self) -> str:
        pct = self.proportion * 100.0
        low = self.wilson_lower * 100.0
        high = self.wilson_upper * 100.0
        return f"{pct:.2f}% (95% CI: [{low:.2f}%, {high:.2f}%])"


@dataclass
class ContinuousStats:
    count: int
    median: float
    q1: float
    q3: float
    iqr: float
    mean: float
    std_dev: float
    min_val: float
    max_val: float

    def formatted(self) -> str:
        return f"Median: {self.median:.2f} ms (IQR: {self.iqr:.2f} ms, Mean: {self.mean:.2f} ± {self.std_dev:.2f} ms)"


@dataclass
class ClassMetrics:
    name: str
    tp: int
    fp: int
    fn: int
    tn: int
    support: int
    precision: float
    recall: float
    f1: float


@dataclass
class ConfusionMatrix:
    classes: List[str]
    matrix: Dict[str, Dict[str, int]]  # [ground_truth][predicted] -> count
    per_class: Dict[str, ClassMetrics]
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_f1: float


class StatisticalAnalyzer:
    """Core statistical engine for experimental evaluation."""

    Z_95 = 1.959963984540054  # Two-tailed 95% standard normal quantile

    @classmethod
    def wilson_interval(
        cls,
        count: int,
        total: int,
        confidence: float = 0.95,
    ) -> ProportionStats:
        """Compute exact Wilson score interval for binomial proportion."""
        if total <= 0:
            return ProportionStats(0, 0, 0.0, 0.0, 0.0, confidence)

        p = count / total
        z = cls.Z_95 if abs(confidence - 0.95) < 1e-4 else 1.95996

        z2 = z * z
        denom = 1.0 + (z2 / total)
        center = (p + (z2 / (2.0 * total))) / denom
        radicand = ((p * (1.0 - p)) / total) + (z2 / (4.0 * (total ** 2)))
        half_width = (z * math.sqrt(max(0.0, radicand))) / denom

        lower = max(0.0, center - half_width)
        upper = min(1.0, center + half_width)

        return ProportionStats(
            count=count,
            total=total,
            proportion=p,
            wilson_lower=lower,
            wilson_upper=upper,
            confidence_level=confidence,
        )

    @classmethod
    def continuous_summary(cls, values: Sequence[float]) -> ContinuousStats:
        """Calculate robust and parametric summary statistics."""
        if not values:
            return ContinuousStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        n = len(values)
        sorted_vals = sorted(values)

        med = float(statistics.median(sorted_vals))

        if n >= 4:
            # Standard quartiles via quantiles (inclusive)
            q = statistics.quantiles(sorted_vals, n=4, method="inclusive")
            q1, q3 = float(q[0]), float(q[2])
        else:
            q1 = float(sorted_vals[0])
            q3 = float(sorted_vals[-1])

        iqr = max(0.0, q3 - q1)
        mean_val = float(statistics.mean(sorted_vals))
        std_val = float(statistics.stdev(sorted_vals)) if n > 1 else 0.0

        return ContinuousStats(
            count=n,
            median=med,
            q1=q1,
            q3=q3,
            iqr=iqr,
            mean=mean_val,
            std_dev=std_val,
            min_val=float(sorted_vals[0]),
            max_val=float(sorted_vals[-1]),
        )

    @classmethod
    def evaluate_classifier(
        cls,
        table: LogTable,
        classes: Optional[List[str]] = None,
    ) -> ConfusionMatrix:
        """Compute full multi-class confusion matrix, precision, recall, and F1."""
        target_classes = classes or ["security_failure", "mtu_fragment", "loss_timeout", "none"]

        # Initialize counts
        matrix: Dict[str, Dict[str, int]] = {
            gt: {pred: 0 for pred in target_classes} for gt in target_classes
        }

        # Normalize strings
        def norm(c: str) -> str:
            val = (c or "none").lower()
            if "security" in val:
                return "security_failure"
            if "mtu" in val or "fragment" in val:
                return "mtu_fragment"
            if "loss" in val or "timeout" in val:
                return "loss_timeout"
            return "none"

        total_samples = 0
        correct_samples = 0

        for r in table:
            gt = norm(r.cause_injected)
            pred = norm(r.cause_label)

            if gt in matrix and pred in matrix[gt]:
                matrix[gt][pred] += 1
                total_samples += 1
                if gt == pred:
                    correct_samples += 1

        # Per-class metrics
        per_class: Dict[str, ClassMetrics] = {}
        total_f1_weighted = 0.0

        for c in target_classes:
            tp = matrix[c][c]
            fp = sum(matrix[other][c] for other in target_classes if other != c)
            fn = sum(matrix[c][other] for other in target_classes if other != c)
            tn = total_samples - (tp + fp + fn)
            support = sum(matrix[c].values())

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2.0 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

            per_class[c] = ClassMetrics(
                name=c,
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
                support=support,
                precision=precision,
                recall=recall,
                f1=f1,
            )
            total_f1_weighted += f1 * support

        accuracy = correct_samples / total_samples if total_samples > 0 else 0.0
        macro_prec = sum(m.precision for m in per_class.values()) / len(target_classes)
        macro_rec = sum(m.recall for m in per_class.values()) / len(target_classes)
        macro_f1 = sum(m.f1 for m in per_class.values()) / len(target_classes)
        weighted_f1 = total_f1_weighted / total_samples if total_samples > 0 else 0.0

        return ConfusionMatrix(
            classes=target_classes,
            matrix=matrix,
            per_class=per_class,
            accuracy=accuracy,
            macro_precision=macro_prec,
            macro_recall=macro_rec,
            macro_f1=macro_f1,
            weighted_f1=weighted_f1,
        )

    @classmethod
    def summarize_baselines(cls, table: LogTable) -> Dict[str, Dict[str, Any]]:
        """Compute comparative performance profiles across all 7 baselines."""
        grouped = table.group_by(lambda r: r.baseline)
        summary: Dict[str, Dict[str, Any]] = {}

        for b_name, b_table in sorted(grouped.items()):
            total = len(b_table)
            success_count = len(b_table.where(outcome=LogOutcome.SUCCESS.value))
            violation_count = len(b_table.where(outcome=LogOutcome.FLOOR_VIOLATION.value))
            unreachable_count = len(b_table.where(outcome=LogOutcome.FLOOR_UNREACHABLE.value))

            success_stats = cls.wilson_interval(success_count, total)
            violation_stats = cls.wilson_interval(violation_count, total)

            # Latency over successful handshakes
            success_records = b_table.where(outcome=LogOutcome.SUCCESS.value)
            latencies = [r.duration_ms for r in success_records]
            latency_stats = cls.continuous_summary(latencies)

            # Bandwidth (size_bytes)
            sizes = [r.size_bytes for r in b_table]
            size_stats = cls.continuous_summary(sizes)

            summary[b_name] = {
                "total_runs": total,
                "success_stats": success_stats,
                "violation_stats": violation_stats,
                "unreachable_count": unreachable_count,
                "latency_stats": latency_stats,
                "size_stats": size_stats,
            }

        return summary
