"""QERIS S4: run_full.py — Execute full experiment matrix (100 reps per cell).

Usage:
    python3 run_full.py [--seed SEED] [--reps N]

Arguments:
    --seed SEED   Random seed for reproducibility (default: 1337)
    --reps N      Handshakes per cell (default: 100, minimum 100 per spec)

Full matrix: ~105 cells × 100 reps = ~10,500 handshakes.
All raw logs are stored immutably under data/raw/<run_id>/.
Figures and tables are regenerated from raw logs — never from intermediates.

Definition of done (S4 spec §8):
  - Every metric in the matrix has data, or a stated reason why not.
  - Every figure regenerates from raw logs with one command.
  - The results section matches the data and states limitations honestly.
"""
import argparse
import sys
import os

# Add parent of qeris/ package so `qeris.s4.*` resolves
_here = os.path.abspath(__file__)                   # .../qeris/qeris/s4/run_full.py
_root = os.path.dirname(os.path.dirname(os.path.dirname(_here)))  # .../qeris/
if _root not in sys.path:
    sys.path.insert(0, _root)

from qeris.s4.experiment_matrix import ExperimentMatrix
from qeris.s4.experiment_runner import ExperimentRunner
from qeris.s4.log_parser import LogParser
from qeris.s4.analysis import StatisticalAnalyzer
from qeris.s4.generate_figures import FigureGenerator
from qeris.s4.generate_tables import TableGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QERIS S4 Full Experiment Runner")
    parser.add_argument("--seed", type=int, default=1337, help="Global random seed")
    parser.add_argument("--reps", type=int, default=100, help="Repetitions per cell (min 100)")
    parser.add_argument("--run-id", type=str, default=None, help="Optional run identifier")
    return parser.parse_args()


def print_section_header(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main() -> None:
    args = parse_args()
    reps = max(args.reps, 100)

    print_section_header("QERIS S4 — Full Benchmark Run")
    print(f"  Seed:  {args.seed}")
    print(f"  Reps:  {reps} handshakes per cell")

    # 1. Full matrix
    cells = ExperimentMatrix.generate_full_matrix(repetitions_per_cell=reps)
    total_hs = sum(c.repetitions for c in cells)
    print(f"  Cells: {len(cells)} × {reps} reps = {total_hs:,} total handshakes")

    # 2. Execute
    print_section_header("Executing Experiment Matrix")
    runner = ExperimentRunner(output_base_dir="data/raw", base_seed=args.seed)
    run_id, raw_path, table = runner.run_matrix(cells, run_id=args.run_id, verbose=True)

    # 3. Analysis
    print_section_header("Statistical Analysis")
    summary = StatisticalAnalyzer.summarize_baselines(table)
    print(f"\n{'Baseline':<32}  {'Success (95%CI)':>28}  {'FloorViol':>10}  {'MedianLat (ms)':>15}  {'IQR':>7}  {'MeanBW(B)':>10}")
    print("-" * 110)
    for b_name, d in sorted(summary.items()):
        s = d["success_stats"]
        v = d["violation_stats"]
        l = d["latency_stats"]
        sz = d["size_stats"]
        s_str = f"{s.proportion*100:.1f}% [{s.wilson_lower*100:.1f}%, {s.wilson_upper*100:.1f}%]"
        lat = f"{l.median:.2f}" if l.count else "N/A"
        iqr = f"±{l.iqr:.2f}" if l.count else "N/A"
        bw  = f"{sz.mean:.0f}" if sz.count else "N/A"
        print(f"{b_name:<32}  {s_str:>28}  {v.proportion*100:>9.1f}%  {lat:>15}  {iqr:>7}  {bw:>10}")

    # 4. Confusion matrix
    print_section_header("Classifier Evaluation (S3 ↔ Ground Truth)")
    cm = StatisticalAnalyzer.evaluate_classifier(table)
    print(f"  Accuracy:     {cm.accuracy*100:.2f}%")
    print(f"  Macro F1:     {cm.macro_f1:.3f}")
    print(f"  Weighted F1:  {cm.weighted_f1:.3f}")
    print(f"\n  {'Class':<22}  {'Precision':>10}  {'Recall':>8}  {'F1':>7}  {'Support':>8}")
    print("  " + "-" * 62)
    for c, m in cm.per_class.items():
        print(f"  {c:<22}  {m.precision*100:>9.1f}%  {m.recall*100:>7.1f}%  {m.f1:>7.3f}  {m.support:>8}")

    # 5. Floor violation audit
    print_section_header("Security Floor Integrity Audit")
    from qeris.s4.log_schema import LogOutcome
    from qeris.s4.log_parser import LogTable
    viol_records = table.where(outcome=LogOutcome.FLOOR_VIOLATION.value)
    full_gw_viols = table.filter(lambda r: r.baseline == "full_gateway" and r.outcome == LogOutcome.FLOOR_VIOLATION.value)
    print(f"  Total floor violations across ALL baselines: {len(viol_records)}")
    print(f"  QERIS Full Gateway floor violations:        {len(full_gw_viols)}  (target: 0)")
    if len(full_gw_viols) == 0:
        print("  [PASS] INVARIANT HOLDS: QERIS never activates a flow below its signed security floor.")
    else:
        print("  [FAIL] INVARIANT VIOLATED — investigate cause immediately!")

    # 6. Figures
    print_section_header("Generating Figures")
    fig_gen = FigureGenerator(output_dir="figures")
    fig_paths = fig_gen.generate_all(table)
    for p in fig_paths:
        print(f"  Saved → {p}")

    # 7. Tables
    print_section_header("Generating Tables")
    tbl_gen = TableGenerator(output_dir="tables")
    tbl_paths = tbl_gen.generate_all(table)
    for k, p in tbl_paths.items():
        print(f"  [{k}] → {p}")

    print_section_header("Run Complete")
    print(f"  Raw logs:   {raw_path}")
    print(f"  Figures:    figures/dashboard.html")
    print(f"  Tables:     tables/")
    print(f"\n  All figures regenerate from raw logs by running:")
    print(f"    python3 qeris/s4/run_full.py --run-id {run_id}")


if __name__ == "__main__":
    main()
