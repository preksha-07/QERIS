"""QERIS S4: Unit and Integration Tests.

Tests cover:
  SCH - Log Schema and Parser
  FI  - Fault Injection engine
  GT  - Ground-Truth Harness
  BE  - Baseline Engine correctness
  AN  - Analysis (Wilson CI, IQR, confusion matrix)
  RUN - End-to-end pilot smoke test
"""
from __future__ import annotations

import io
import json
import math
import sys
import os
import unittest

# Flat imports: conftest.py adds s4/ and s3/ to sys.path
from log_schema import (
    Baseline, CryptoMode, DeviceClass, LogEvent, LogOutcome,
    LogRecord, SensitivityTier, create_log_record,
)
from log_parser import LogParser, LogTable
from fault_injection import (
    FaultType, GilbertElliottParams, SoftwareFaultSimulator,
)
from ground_truth_harness import GroundTruthHarness
from experiment_matrix import ExperimentCell, ExperimentMatrix
from baseline_engine import BaselineEngine
from analysis import StatisticalAnalyzer
from experiment_runner import ExperimentRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(**kwargs) -> LogRecord:
    defaults = dict(
        run_id="test-run", scenario="normal_pqc", baseline="full_gateway",
        device_id="dev-01", device_class="esp32_constrained",
        flow_id="flow_critical_01", sensitivity="CRITICAL",
        event="handshake_complete", mode="PQC",
        cause_label="none", cause_injected="none",
        size_bytes=1820, duration_ms=94.0, cpu_pct=84.0, mem_mb=0.22,
        outcome="SUCCESS",
    )
    defaults.update(kwargs)
    return create_log_record(**defaults)


# ---------------------------------------------------------------------------
# SCH: Log Schema Tests
# ---------------------------------------------------------------------------

class TestSCH_Schema(unittest.TestCase):

    def test_SCH1_create_and_serialise_roundtrip(self):
        r = _make_record()
        j = r.to_json()
        r2 = LogRecord.from_json(j)
        self.assertEqual(r.run_id, r2.run_id)
        self.assertEqual(r.duration_ms, r2.duration_ms)
        self.assertEqual(r.outcome, r2.outcome)

    def test_SCH2_all_required_fields_present(self):
        r = _make_record()
        d = r.to_dict()
        required = [
            "ts", "run_id", "scenario", "baseline", "device_id", "device_class",
            "flow_id", "sensitivity", "event", "mode", "cause_label",
            "cause_injected", "size_bytes", "duration_ms", "cpu_pct", "mem_mb", "outcome",
        ]
        for field in required:
            self.assertIn(field, d, f"Missing field: {field}")

    def test_SCH3_ts_is_int_epoch_ms(self):
        r = _make_record()
        self.assertIsInstance(r.ts, int)
        self.assertGreater(r.ts, 0)

    def test_SCH4_from_dict_roundtrip(self):
        d = _make_record().to_dict()
        r = LogRecord.from_dict(d)
        self.assertEqual(r.scenario, "normal_pqc")

    def test_SCH5_from_json_invalid_raises(self):
        with self.assertRaises(Exception):
            LogRecord.from_json("{invalid json")

    def test_SCH6_log_table_where_filters(self):
        t = LogTable([_make_record(outcome="SUCCESS"), _make_record(outcome="REJECT")])
        self.assertEqual(len(t.where(outcome="SUCCESS")), 1)
        self.assertEqual(len(t.where(outcome="REJECT")), 1)

    def test_SCH7_log_table_column_extraction(self):
        t = LogTable([_make_record(duration_ms=50.0), _make_record(duration_ms=100.0)])
        cols = t.column("duration_ms")
        self.assertEqual(cols, [50.0, 100.0])

    def test_SCH8_log_parser_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            LogParser.parse_file("/nonexistent/path/test.jsonl")


# ---------------------------------------------------------------------------
# FI: Fault Injection Tests
# ---------------------------------------------------------------------------

class TestFI_FaultInjection(unittest.TestCase):

    def test_FI1_no_fault_always_succeeds(self):
        sim = SoftwareFaultSimulator(seed=42, loss_model=FaultType.NONE)
        for _ in range(20):
            r = sim.evaluate_transmission(packet_size=800, simulated_delay_ms=10.0)
            self.assertTrue(r["success"])
            self.assertEqual(r["cause"], "none")

    def test_FI2_mtu_fragment_detected_when_packet_exceeds_path_mtu(self):
        sim = SoftwareFaultSimulator(seed=42, path_mtu=576, loss_model=FaultType.NONE)
        r = sim.evaluate_transmission(packet_size=1820, fragment_size=2000, simulated_delay_ms=5.0)
        self.assertFalse(r["success"])
        self.assertEqual(r["cause"], "mtu_fragment")

    def test_FI3_mtu_success_when_fragment_fits(self):
        sim = SoftwareFaultSimulator(seed=42, path_mtu=1500, loss_model=FaultType.NONE)
        r = sim.evaluate_transmission(packet_size=240, fragment_size=240, simulated_delay_ms=5.0)
        self.assertTrue(r["success"])

    def test_FI4_timeout_cause_when_delay_exceeds_budget(self):
        sim = SoftwareFaultSimulator(seed=42, path_mtu=1500, timeout_budget_ms=100.0, loss_model=FaultType.NONE)
        r = sim.evaluate_transmission(packet_size=240, simulated_delay_ms=200.0)
        self.assertFalse(r["success"])
        self.assertEqual(r["cause"], "loss_timeout")

    def test_FI5_security_attack_always_fails_as_security_failure(self):
        sim = SoftwareFaultSimulator(seed=42, loss_model=FaultType.NONE)
        r = sim.evaluate_transmission(packet_size=240, is_security_attack=True)
        self.assertFalse(r["success"])
        self.assertEqual(r["cause"], "security_failure")

    def test_FI6_uniform_loss_seed_reproducible(self):
        sim1 = SoftwareFaultSimulator(seed=99, loss_model=FaultType.UNIFORM_LOSS, uniform_loss_rate=0.5)
        sim2 = SoftwareFaultSimulator(seed=99, loss_model=FaultType.UNIFORM_LOSS, uniform_loss_rate=0.5)
        results1 = [sim1.evaluate_transmission(500)["success"] for _ in range(50)]
        results2 = [sim2.evaluate_transmission(500)["success"] for _ in range(50)]
        self.assertEqual(results1, results2)

    def test_FI7_ge_burst_loss_higher_loss_than_uniform(self):
        sim_ge = SoftwareFaultSimulator(
            seed=1, loss_model=FaultType.BURST_LOSS,
            ge_params=GilbertElliottParams(p=0.3, r=0.1, loss_prob_g=0.01, loss_prob_b=0.99),
        )
        sim_clean = SoftwareFaultSimulator(seed=1, loss_model=FaultType.NONE)
        ge_losses = sum(1 for _ in range(100) if not sim_ge.evaluate_transmission(500)["success"])
        clean_losses = sum(1 for _ in range(100) if not sim_clean.evaluate_transmission(500)["success"])
        self.assertGreater(ge_losses, clean_losses)


# ---------------------------------------------------------------------------
# GT: Ground-Truth Harness Tests
# ---------------------------------------------------------------------------

class TestGT_GroundTruth(unittest.TestCase):

    def test_GT1_normal_scenario_has_none_cause(self):
        gt = GroundTruthHarness.get_ground_truth("normal_pqc")
        self.assertEqual(gt.injected_cause, "none")
        self.assertEqual(gt.expected_outcome, "SUCCESS")

    def test_GT2_attack_scenarios_classified_as_security_failure(self):
        for s in ["attack_bad_signature", "attack_replayed_policy", "attack_downgrade_attempt", "attack_untrusted_authority"]:
            gt = GroundTruthHarness.get_ground_truth(s)
            self.assertEqual(gt.injected_cause, "security_failure", f"Unexpected cause for {s}")
            self.assertEqual(gt.expected_outcome, "REJECT", f"Expected REJECT for {s}")

    def test_GT3_mtu_scenarios_classified_correctly(self):
        for s in ["reduced_mtu_1280", "reduced_mtu_576"]:
            gt = GroundTruthHarness.get_ground_truth(s)
            self.assertEqual(gt.injected_cause, "mtu_fragment", f"Wrong cause for {s}")

    def test_GT4_loss_scenarios_classified_correctly(self):
        for s in ["packet_loss_uniform_5pct", "packet_loss_burst_ge", "path_timeout"]:
            gt = GroundTruthHarness.get_ground_truth(s)
            self.assertEqual(gt.injected_cause, "loss_timeout", f"Wrong cause for {s}")

    def test_GT5_match_prediction_exact(self):
        self.assertTrue(GroundTruthHarness.match_prediction("security_failure", "security_failure"))
        self.assertTrue(GroundTruthHarness.match_prediction("loss_timeout", "loss_timeout"))
        self.assertTrue(GroundTruthHarness.match_prediction("mtu_fragment", "mtu_fragment"))

    def test_GT6_match_prediction_mismatch(self):
        self.assertFalse(GroundTruthHarness.match_prediction("security_failure", "loss_timeout"))
        self.assertFalse(GroundTruthHarness.match_prediction("mtu_fragment", "security_failure"))

    def test_GT7_unknown_scenario_defaults_gracefully(self):
        gt = GroundTruthHarness.get_ground_truth("nonexistent_scenario_xyz")
        self.assertEqual(gt.injected_cause, "none")


# ---------------------------------------------------------------------------
# BE: Baseline Engine Tests
# ---------------------------------------------------------------------------

class TestBE_BaselineEngine(unittest.TestCase):

    def _clean_engine(self, mtu: int = 9000) -> BaselineEngine:
        sim = SoftwareFaultSimulator(seed=42, path_mtu=mtu, loss_model=FaultType.NONE)
        return BaselineEngine(sim, seed=42)

    def test_BE1_static_pqc_succeeds_on_clean_channel(self):
        engine = self._clean_engine()
        r = engine.execute_handshake(Baseline.STATIC_PQC, "normal_pqc", DeviceClass.STANDARD_COMPUTE, SensitivityTier.CRITICAL)
        self.assertEqual(r.outcome, LogOutcome.SUCCESS)
        self.assertEqual(r.mode, CryptoMode.PQC)
        self.assertFalse(r.floor_violation)

    def test_BE2_static_classical_rejected_on_critical_flow(self):
        engine = self._clean_engine()
        r = engine.execute_handshake(Baseline.STATIC_CLASSICAL, "normal_pqc", DeviceClass.STANDARD_COMPUTE, SensitivityTier.CRITICAL)
        # Classical cannot satisfy CRITICAL floor (PQC required)
        self.assertEqual(r.outcome, LogOutcome.REJECT)
        self.assertFalse(r.floor_violation)

    def test_BE3_attack_rejected_by_full_gateway(self):
        engine = self._clean_engine()
        r = engine.execute_handshake(Baseline.FULL_GATEWAY, "attack_bad_signature", DeviceClass.STANDARD_COMPUTE, SensitivityTier.CRITICAL)
        self.assertEqual(r.outcome, LogOutcome.REJECT)
        self.assertEqual(r.cause_label, "security_failure")
        self.assertFalse(r.floor_violation, "QERIS must never lower the floor to reject an attack")

    def test_BE4_downgrade_on_failure_violates_floor_under_attack(self):
        engine = self._clean_engine()
        r = engine.execute_handshake(Baseline.DOWNGRADE_ON_FAILURE, "attack_downgrade_attempt", DeviceClass.STANDARD_COMPUTE, SensitivityTier.CRITICAL)
        self.assertEqual(r.outcome, LogOutcome.FLOOR_VIOLATION)
        self.assertTrue(r.floor_violation)

    def test_BE5_floor_unreachable_classical_device_on_critical_flow(self):
        engine = self._clean_engine()
        r = engine.execute_handshake(
            Baseline.FULL_GATEWAY, "floor_unreachable_classical_device",
            DeviceClass.ESP32_CONSTRAINED, SensitivityTier.CRITICAL,
            device_supported_modes=[CryptoMode.CLASSICAL],
        )
        self.assertEqual(r.outcome, LogOutcome.FLOOR_UNREACHABLE)
        self.assertFalse(r.floor_violation)

    def test_BE6_full_gateway_never_violates_floor_on_attacks(self):
        engine = self._clean_engine()
        attack_scenarios = [
            "attack_bad_signature", "attack_replayed_policy",
            "attack_downgrade_attempt", "attack_untrusted_authority",
        ]
        for sc in attack_scenarios:
            r = engine.execute_handshake(Baseline.FULL_GATEWAY, sc, DeviceClass.STANDARD_COMPUTE, SensitivityTier.CRITICAL)
            self.assertFalse(r.floor_violation, f"Floor violated on {sc} under Full Gateway — INVARIANT BREACH!")


# ---------------------------------------------------------------------------
# AN: Analysis Tests
# ---------------------------------------------------------------------------

class TestAN_Analysis(unittest.TestCase):

    def test_AN1_wilson_interval_symmetric_at_half(self):
        stats = StatisticalAnalyzer.wilson_interval(50, 100)
        self.assertAlmostEqual(stats.proportion, 0.5, places=2)
        self.assertGreater(stats.wilson_upper, 0.5)
        self.assertLess(stats.wilson_lower, 0.5)

    def test_AN2_wilson_zero_events(self):
        stats = StatisticalAnalyzer.wilson_interval(0, 100)
        self.assertEqual(stats.proportion, 0.0)
        self.assertGreaterEqual(stats.wilson_lower, 0.0)
        self.assertLessEqual(stats.wilson_upper, 1.0)

    def test_AN3_wilson_all_events(self):
        stats = StatisticalAnalyzer.wilson_interval(100, 100)
        self.assertEqual(stats.proportion, 1.0)
        self.assertGreater(stats.wilson_lower, 0.9)

    def test_AN4_wilson_total_zero(self):
        stats = StatisticalAnalyzer.wilson_interval(0, 0)
        self.assertEqual(stats.proportion, 0.0)

    def test_AN5_continuous_summary_median_iqr(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        stats = StatisticalAnalyzer.continuous_summary(values)
        self.assertAlmostEqual(stats.median, 30.0, places=1)
        self.assertAlmostEqual(stats.iqr, 20.0, places=1)

    def test_AN6_continuous_summary_empty(self):
        stats = StatisticalAnalyzer.continuous_summary([])
        self.assertEqual(stats.count, 0)
        self.assertEqual(stats.median, 0.0)

    def test_AN7_continuous_summary_single_value(self):
        stats = StatisticalAnalyzer.continuous_summary([42.0])
        self.assertEqual(stats.median, 42.0)
        self.assertEqual(stats.iqr, 0.0)

    def test_AN8_confusion_matrix_perfect_classifier(self):
        """Classifier that always matches ground truth."""
        records = [
            _make_record(cause_injected="security_failure", cause_label="security_failure"),
            _make_record(cause_injected="security_failure", cause_label="security_failure"),
            _make_record(cause_injected="mtu_fragment", cause_label="mtu_fragment"),
            _make_record(cause_injected="loss_timeout", cause_label="loss_timeout"),
            _make_record(cause_injected="none", cause_label="none"),
        ]
        table = LogTable(records)
        cm = StatisticalAnalyzer.evaluate_classifier(table)
        self.assertAlmostEqual(cm.accuracy, 1.0, places=2)
        self.assertAlmostEqual(cm.macro_f1, 1.0, places=2)

    def test_AN9_confusion_matrix_security_never_misclassified_as_loss(self):
        """Security failures should never be misclassified as loss/timeout — critical invariant."""
        records = [
            _make_record(cause_injected="security_failure", cause_label="security_failure"),
            _make_record(cause_injected="security_failure", cause_label="security_failure"),
            _make_record(cause_injected="loss_timeout", cause_label="loss_timeout"),
        ]
        table = LogTable(records)
        cm = StatisticalAnalyzer.evaluate_classifier(table)
        # security_failure should have 0 FP in loss_timeout column
        self.assertEqual(cm.matrix["security_failure"]["loss_timeout"], 0)
        self.assertEqual(cm.matrix["security_failure"]["mtu_fragment"], 0)

    def test_AN10_summarize_baselines_returns_all_7(self):
        pilot = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=3)
        runner = ExperimentRunner(output_base_dir="/tmp/qeris_test_runs")
        _, _, table = runner.run_matrix(pilot, run_id="test_summary", verbose=False)
        summary = StatisticalAnalyzer.summarize_baselines(table)
        self.assertEqual(len(summary), 7)

    def test_AN11_floor_invariant_full_gateway_zero_violations(self):
        """Full gateway must produce ZERO floor violations in any clean pilot run."""
        pilot = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=5)
        runner = ExperimentRunner(output_base_dir="/tmp/qeris_test_runs")
        _, _, table = runner.run_matrix(pilot, run_id="test_floor_invariant", verbose=False)
        full_gw_viols = table.filter(
            lambda r: r.baseline == "full_gateway" and r.outcome == LogOutcome.FLOOR_VIOLATION.value
        )
        self.assertEqual(
            len(full_gw_viols), 0,
            f"INVARIANT VIOLATED: QERIS Full Gateway produced {len(full_gw_viols)} floor violations!"
        )


# ---------------------------------------------------------------------------
# RUN: End-to-end smoke test
# ---------------------------------------------------------------------------

class TestRUN_EndToEnd(unittest.TestCase):

    def test_RUN1_pilot_matrix_generates_correct_cell_count(self):
        cells = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=10)
        # 7 baselines × 5 key scenarios = 35 cells
        self.assertEqual(len(cells), 35)

    def test_RUN2_full_matrix_has_enough_cells(self):
        cells = ExperimentMatrix.generate_full_matrix(repetitions_per_cell=100)
        # 7 baselines × 15 scenarios = 105
        self.assertEqual(len(cells), 105)

    def test_RUN3_pilot_run_produces_records(self):
        cells = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=3)
        runner = ExperimentRunner(output_base_dir="/tmp/qeris_test_runs", base_seed=42)
        _, _, table = runner.run_matrix(cells, run_id="test_e2e_pilot", verbose=False)
        self.assertGreater(len(table), 0)

    def test_RUN4_raw_log_file_written_and_parseable(self):
        import tempfile
        cells = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=2)
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = ExperimentRunner(output_base_dir=tmpdir, base_seed=1)
            _, raw_path, original_table = runner.run_matrix(cells, run_id="test_parse", verbose=False)
            reparsed = LogParser.parse_file(raw_path)
            self.assertEqual(len(original_table), len(reparsed))

    def test_RUN5_figures_and_tables_generate_without_error(self):
        import tempfile
        cells = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=3)
        runner = ExperimentRunner(output_base_dir="/tmp/qeris_test_runs", base_seed=7)
        _, _, table = runner.run_matrix(cells, run_id="test_figs", verbose=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            from generate_figures import FigureGenerator
            from generate_tables import TableGenerator
            figs = FigureGenerator(output_dir=tmpdir).generate_all(table)
            tables = TableGenerator(output_dir=tmpdir).generate_all(table)
            self.assertEqual(len(figs), 6)
            self.assertEqual(len(tables), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
