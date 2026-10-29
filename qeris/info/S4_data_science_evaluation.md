# S4 - Data Science and Evaluation Lead (48 hours)

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway
**Contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes
**Teammates:** S1 (crypto/device), S2 (gateway/cloud), S3 (state machine/recovery)

## 1. Your mission
Turn the system into evidence. You design the experiments, inject the faults, collect and analyze the data, and write the evaluation. You do not build the gateway.

## 2. Responsibilities
**Primary:** experiment design and matrix, log schema and parser, network fault injection, experiment runner, data collection runs, ground-truth cause labelling, statistics, graphs and tables, evaluation and results sections, PPT, viva question bank.
**Secondary:** related work from the prior-art report, limitations.
**Backup for:** cloud API (S2), failure taxonomy (S3), device logging (S1).

## 3. Tasks

| ID | Task | Hours | Weeks | Depends on | Deliverable |
|----|------|-------|-------|------------|-------------|
| T22a | Log schema and parser | 3 | 1-2 | T2 | Schema, parser |
| T28 | Experiment design and matrix | 5 | 1-4 | T19, T22a | Design doc, matrix |
| T21 | Network fault injection (tc netem: burst loss, MTU, reorder, delay) | 5 | 2-5 | T2 | Scripts |
| T29 | Experiment runner and automation | 6 | 5-7 | T21, T23a | Scripts |
| T31 | Ground-truth cause-labelling harness | 2 | 6 | T19, T21 | Injected-cause labels |
| T30 | Data collection: pilot then full runs | 6 | 7-9 | T29, T20 | Raw logs |
| T32 | Analysis and statistics | 6 | 8-10 | T30 | Cleaned data, stats |
| T33 | Graphs and tables | 4 | 10-11 | T32 | Paper-ready figures |
| T34 | Paper: evaluation methodology, results, limitations, related work | 5 | 11-12 | T32 | Draft text |
| T35 | PPT | 3 | 12 | T34 | Deck |
| T37 | Viva question bank for the whole team | 3 | 13 | T34 | Question bank |

## 4. Weekly plan

| Week | Hours | Work |
|------|-------|------|
| 1 | 3 | T22a (2h); T28 draft (1h) |
| 2 | 2 | T22a (1h); T21 start (1h) |
| 3 | 3 | T21 (2h); T28 (1h) |
| 4 | 3 | T28 matrix final (3h) |
| 5 | 4 | T21 finish (2h); T29 (2h) |
| 6 | 4 | T29 (2h); T31 (2h) |
| 7 | 4 | T29 (2h); pilot runs (2h) |
| 8 | 3 | Full runs (2h); analysis pipeline (1h) |
| 9 | 4 | Full runs (2h); analysis (2h) |
| 10 | 5 | Analysis (3h); graphs (2h) |
| 11 | 5 | Graphs (2h); paper (3h) |
| 12 | 5 | Paper (2h); PPT (3h) |
| 13 | 3 | Viva question bank |

Peak weeks: 6-12.

## 5. Experiment design

**Baselines**
1. Static Classical.
2. Static Hybrid.
3. Static PQC.
4. Sensitivity-only gateway (no cause-aware recovery).
5. Downgrade-on-failure.
6. Static retry with the floor.
7. Full gateway.
Optional ablations: no classifier, no floor monitor.

**Factors:** device class (emulated classes plus ESP32), loss model (none, uniform, burst), MTU levels, parameter sets, sensitivity level.

**Scenarios:** normal, reduced MTU, packet loss, reordering, duplicates, timeout, memory pressure, classical-only device on a Critical flow, invalid signature, modified policy, replayed policy, downgrade attempt, gateway restart, policy update during a session, capability mismatch, recovery after quarantine. Flooding is optional.

**Metrics:** handshake success, recovery success, security-floor violation rate, downgrade-block rate, replay rejection, invalid-policy rejection, classification accuracy (confusion matrix, per-class precision, recall, F1), latency, bandwidth, CPU, memory, fragment count, retransmissions, Critical-flow availability.

## 6. Statistics and rigor
- At least 100 handshakes per cell for success rates, or a stated reason where that is impossible (for example ESP32 runs).
- Report median and IQR for latency. Mean and standard deviation where the distribution justifies it.
- Use Wilson intervals for success rates. Do not use confidence intervals where assumptions do not hold.
- Claim causality only from controlled ablations, not from correlation.
- Keep raw logs immutable. Every graph must regenerate from raw logs with one script.
- Calibrate emulated device classes with S1's ESP32 data, and say that one real device class is a threat to validity.
- List confounders: Wi-Fi interference on the ESP32 path, emulated versus real CPU behavior, library differences.

## 7. Interfaces
- **Gets from S1 and S2:** logs in your schema, baselines by config flag.
- **Gets from S3:** cause labels and the recovery controller for full runs.
- **Gives everyone:** metrics definitions, run scripts, plots, and the limitations text.

## 8. Definition of done
- Every metric in the matrix has data, or a stated reason why not.
- Every figure regenerates from raw logs with one command.
- The results section matches the data and states limitations honestly.
- The viva bank covers every component, with model answers reviewed by the owner of each part.

## 9. Risks and fallbacks
- netem does not affect the ESP32 path: emulate faults in-process and validate a subset on hardware.
- Too little data: reduce factor levels, not repetitions.
- Compute failures absent: report that finding and remove the class from the matrix.
- Late recovery controller: run baselines first, then add the full gateway.

## 10. Viva topics to master
Why these baselines; how you avoid unsupported causal claims; what the confusion matrix shows; why one ESP32 is a limitation; how emulated classes were calibrated; what a null result would mean.

## 11. Approval
You own the experiment matrix and metrics. S3 reviews changes. The matrix is frozen after Week 9 except by team decision. You do not publish or share results publicly; that needs the mentor, all four students and the IP office.

---

# Add-on: What to do and how to do it

## A. Log schema (Week 1-2)
One JSON object per line, UTC timestamps in milliseconds:
`ts, run_id, scenario, baseline, device_id, device_class, flow_id, sensitivity, event, mode, cause_label, cause_injected, size_bytes, duration_ms, cpu_pct, mem_mb, outcome`.
Events to cover: connection start, handshake complete, data sent, failure, retry, policy rejected, replay detected, downgrade blocked, quarantine. Publish the schema to the team in Week 1 and freeze it in Week 2. Write a parser that loads all logs into a table.

## B. Fault injection (Week 2-5)
Run on the gateway machine, applied to the network interface toward the device. Check exact syntax on your system with `man tc-netem`.
- Uniform loss: `tc qdisc add dev <if> root netem loss 5%`
- Burst loss (Gilbert-Elliott): `tc qdisc change dev <if> root netem loss gemodel <p> <r> <1-h> <1-k>`
- Delay and jitter: `netem delay 50ms 10ms`
- Reorder: `netem delay 10ms reorder 25% 50%`
- Duplicates: `netem duplicate 1%`
- Reduced MTU: `ip link set dev <if> mtu 1280` (or smaller)
Write one shell or Python function per scenario, with `setup` and `teardown`, so each run starts clean. If netem does not affect the ESP32 path, emulate faults in the gateway process and confirm a subset on hardware.

## C. Ground-truth labels (Week 6)
Every injected fault writes the true cause into `cause_injected` in the same log stream. The classifier's guess goes into `cause_label`. Accuracy is then a comparison of two columns.

## D. Experiment matrix (Week 1-4)
Write it as a spreadsheet or YAML: rows are scenario x baseline x device class x parameter set. For every row state the metric list and the repetition count (at least 100 handshakes per cell, or an explicit reason). Randomize run order, fix random seeds, discard a few warm-up runs, and record machine, library version and kernel in each run's metadata.

## E. Runner (Week 5-8)
A script reads the matrix, applies a scenario, starts the system with the baseline config, runs N handshakes, stores logs under `data/raw/<run_id>/`, then tears down. Never edit raw logs by hand.

## F. Analysis (Week 8-10)
Suggested tools: Python with `pandas`, `scipy`, `statsmodels`, `matplotlib`.
- Latency: median and IQR (also mean and standard deviation where the distribution is reasonable).
- Success rate: proportion with a Wilson interval (`statsmodels.stats.proportion.proportion_confint`, method `wilson`).
- Classifier: confusion matrix; per-class precision, recall, F1 (`sklearn.metrics`); report class counts because rare classes distort averages.
- Security metrics: floor-violation count (target zero), downgrade-block rate, replay rejection rate.
- Overhead: bandwidth (bytes per handshake), fragment count, retransmissions, CPU, memory.

## G. Graphs and tables (Week 10-11)
Minimum set: latency by security mode; bandwidth overhead classical versus hybrid versus PQC; handshake success versus loss rate for all baselines; recovery success by cause; confusion matrix; Critical-flow availability during faults; a table of baselines versus full gateway on security, latency, bandwidth and reliability. One script generates all figures from raw data, saving PDF or PNG with fixed sizes.

## H. Writing (Week 11-12)
- **Methodology:** platform, device classes, calibration against the ESP32, scenarios, baselines, metrics, repetitions, statistics.
- **Results:** state what happened, not why, unless an ablation supports the why.
- **Limitations:** emulated devices, one real device class, controlled network, small scale, one library.
- **Related work:** use the prior-art report; cite only sources you have opened yourselves.

## I. Pitfalls
- Changing the matrix or schema late.
- Reporting averages without spread.
- Claiming causes without controlled comparison.
- Cherry-picking runs: report failures too.
- Losing raw data: keep it in version control or a dated backup.

## J. Handoffs
- Week 2: schema to all.
- Week 5: fault-injection scripts to S2 and S1 for testing.
- Week 9: analysis pipeline validated on pilot data.
- Week 12: figures and results to the whole team for review.
