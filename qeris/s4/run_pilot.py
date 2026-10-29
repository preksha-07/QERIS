"""QERIS S4: run_pilot.py — Execute pilot experiment matrix.

Usage:
    python3 run_pilot.py

Runs a fast pilot matrix (~35 cells × 10 reps = 350 handshakes) to validate
log schema, analysis pipeline and figure generation before the full benchmark.
Outputs:
  data/raw/pilot_<timestamp>/raw_events.jsonl
  data/raw/pilot_<timestamp>/run_metadata.json
  figures/figure*.svg
  figures/dashboard.html
  tables/table*.md  tables/table*.tex
"""
import sys
import os

# Add parent of qeris/ package so `qeris.s4.*` resolves
_here = os.path.abspath(__file__)                   # .../qeris/qeris/s4/run_pilot.py
_root = os.path.dirname(os.path.dirname(os.path.dirname(_here)))  # .../qeris/
if _root not in sys.path:
    sys.path.insert(0, _root)

from qeris.s4.experiment_matrix import ExperimentMatrix
from qeris.s4.experiment_runner import ExperimentRunner
from qeris.s4.log_parser import LogParser
from qeris.s4.analysis import StatisticalAnalyzer
from qeris.s4.generate_figures import FigureGenerator
from qeris.s4.generate_tables import TableGenerator


def main() -> None:
    print("=" * 60)
    print("QERIS S4 — Pilot Experiment Run")
    print("=" * 60)

    # 1. Generate pilot matrix (10 reps per cell for speed)
    cells = ExperimentMatrix.generate_pilot_matrix(repetitions_per_cell=10)
    print(f"[*] Pilot matrix: {len(cells)} cells  (×10 reps = {len(cells)*10} handshakes)")

    # 2. Run
    runner = ExperimentRunner(output_base_dir="data/raw", base_seed=1337)
    run_id, raw_path, table = runner.run_matrix(cells, verbose=True)

    # 3. Analysis summary
    print("\n[*] Running statistical analysis...")
    summary = StatisticalAnalyzer.summarize_baselines(table)
    print(f"\n{'Baseline':<32}  {'SuccessRate':>12}  {'FloorViol':>10}  {'MedianMs':>9}  {'BW(B)':>7}")
    print("-" * 76)
    for b_name, d in sorted(summary.items()):
        s = d["success_stats"]
        v = d["violation_stats"]
        l = d["latency_stats"]
        sz = d["size_stats"]
        lat = f"{l.median:.1f}" if l.count else "N/A"
        bw = f"{sz.mean:.0f}" if sz.count else "N/A"
        print(f"{b_name:<32}  {s.proportion*100:>10.1f}%  {v.proportion*100:>9.1f}%  {lat:>9}  {bw:>7}")

    # 4. Classifier performance
    print("\n[*] Classifier performance (S3 ↔ ground truth)...")
    cm = StatisticalAnalyzer.evaluate_classifier(table)
    print(f"    Accuracy:       {cm.accuracy*100:.2f}%")
    print(f"    Macro F1:       {cm.macro_f1:.3f}")
    print(f"    Weighted F1:    {cm.weighted_f1:.3f}")

    # 5. Figures
    print("\n[*] Generating figures...")
    fig_gen = FigureGenerator(output_dir="figures")
    paths = fig_gen.generate_all(table)
    for p in paths:
        print(f"    Saved → {p}")

    # 6. Tables
    print("\n[*] Generating tables...")
    tbl_gen = TableGenerator(output_dir="tables")
    tbl_paths = tbl_gen.generate_all(table)
    for k, p in tbl_paths.items():
        print(f"    [{k}] → {p}")

    print(f"\n[+] Pilot complete. Raw logs at: {raw_path}")
    print("[+] Open figures/dashboard.html in a browser to review all figures.")


if __name__ == "__main__":
    main()
