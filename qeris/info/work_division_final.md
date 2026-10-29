# Final Work Division: Four-Person Team

**Project:** A Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems
**Main contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes
**Budget:** 4 students x ~48 person-hours = ~192 hours, 13 weeks. No new modules added.

## 0. Read this first (three flags)

1. **Hours mismatch.** Three 2-hour sessions per week for 13 weeks is 78 hours per student (312 total), but the plan budget is 48 hours per student. This document plans **48 hours of assigned tasks per student**. The remaining session time is **debugging and integration buffer**, not extra scope. If your real availability is 48 hours only, keep the sessions but expect to use roughly 60 percent of them.
2. **Formal model check.** A bounded model check of the state machine was in the earlier agreed scope but is not in your module list. It is kept as a small "simplify-second" item (2 h, S3). Drop it if scope tightens.
3. **Protocol route is decided at the Week-1 gate.** Route A: DTLS 1.3 with post-quantum groups (e.g. via wolfSSL/OpenSSL 3.5) on ESP32 and gateway. Route B (fallback): simplified authenticated prototype using liboqs on laptop/Pi, with the ESP32 used to measure primitives and run a reduced set. Do not invent a new handshake or key combiner in either route.

**Mapping from your earlier role PDFs:** CSE A (device) becomes S1's device half. The Cyber Security role splits: cryptography goes to S1, policy schema and sensitivity to S2, replay/downgrade/failure logic to S3. CSE B (gateway/cloud) becomes S2. Data Science stays S4 with its responsibilities preserved.

---

## 1. Roles

### S1 - Cryptography and Device Engineer (48 h)
- **Primary:** crypto library setup, ML-KEM, ML-DSA, AEAD session layer, ESP32 integration, device simulator with device profiles and resource classes, device-side logging, ESP32 calibration runs.
- **Secondary:** crypto and device paper sections, known-answer tests and key-handling review, viva prep on keys and sessions.
- **Deliverables:** shared crypto module, ESP32 build and measurements, device simulator, device logs, crypto/device paper sections.
- **Backup for:** ML-DSA signing (S3 backs up S1), gateway service (S2's critical task), replay logic.
- **Dependencies:** S2 interface spec (Week 1-2); S4 log schema.
- **Highest workload weeks:** 1, 2-7 (steady), 8-9 (calibration).
- **Definition of done:** ESP32 completes a handshake and encrypted message exchange with the gateway on the chosen route; timings and memory recorded; all crypto calls covered by known-answer or round-trip tests; no keys or secrets in logs.

### S2 - Gateway, Cloud and Integration Engineer (48 h)
- **Primary:** architecture and interface spec, gateway service, cloud API/DB, policy schema, sensitivity classification, capability registry, readiness rules, persistent policy-version storage, audit logging and rate limiting, static and adaptive baselines, final integration and Docker, demo.
- **Secondary:** gateway/cloud paper sections and architecture diagrams, viva prep.
- **Deliverables:** running gateway and cloud, policy schema document, registry, readiness rules, baseline configurations, Docker/compose, demo script.
- **Backup for:** state machine and recovery controller (S3), ML-KEM handshake (S1), ESP32 integration.
- **Dependencies:** S1 crypto module; S3 state machine interface.
- **Highest workload weeks:** 3-6, 10-11.
- **Definition of done:** device -> gateway -> cloud works end to end for all sensitivity levels; all seven baselines runnable by a config flag; one command starts the system.

### S3 - Security Logic and Recovery Engineer (48 h)
- **Primary:** requirements and threat model, security-floor state machine with invariant monitor, failure taxonomy, recovery controller, replay protection (including fast-forward bound), downgrade rejection, attack tests, invention-disclosure notes.
- **Secondary:** optional model check, security/state-machine/recovery paper sections including abstract and contribution statement, viva prep.
- **Deliverables:** threat model, state machine spec and code, invariant tests, recovery controller, attack test report.
- **Backup for:** policy signing (S1), policy schema and sensitivity (S2), failure-cause logging (S4).
- **Dependencies:** S2 policy schema and version storage; S1 signature verification; S4 fault-injection labels.
- **Highest workload weeks:** 4-9.
- **Definition of done:** all seven invariants have passing tests; every attack test is rejected and logged; recovery never activates a flow below its floor across all injected failures.

### S4 - Data Science and Evaluation Lead (48 h)
- **Primary:** experiment design and matrix, log schema and parser, network fault injection scripts, experiment runner, data collection runs, ground-truth cause labelling harness, statistics, graphs and tables, evaluation and results paper sections, PPT, viva question bank.
- **Secondary:** related-work write-up from the prior-art report, limitations.
- **Deliverables:** experiment design document, fault-injection and runner scripts, cleaned datasets, graphs and tables, results section, PPT, viva bank.
- **Backup for:** cloud API (S2), failure taxonomy (S3), device logging (S1).
- **Dependencies:** logging hooks from S1 and S2; recovery controller from S3 (for full runs).
- **Highest workload weeks:** 6-12.
- **Definition of done:** every metric in the matrix has data from at least 100 handshakes per cell or a stated reason why not; every graph regenerates from raw logs with one script; results section matches the data.

---

## 2. Workload balance

| Student | Implementation h | Analysis/documentation h | Total |
|---------|------------------|--------------------------|-------|
| S1 | 37 | 11 | 48 |
| S2 | 40 | 8 | 48 |
| S3 | 31 | 17 | 48 |
| S4 | 25 | 23 | 48 |

Every student has both an implementation task and an analysis or documentation task. No student owns only documentation.

---

## 3. Task table

| ID | Task | Primary (h) | Backup | Dependency | Week | Deliverable |
|----|------|-------------|--------|------------|------|-------------|
| T1 | Requirements and threat model | S3 (4) | S1 | none | 1-2 | Threat model doc |
| T2 | Architecture and interface spec | S2 (3) | S1 | T1 | 1-2 | Architecture, message formats, API contracts |
| T3 | Crypto library setup | S1 (4) | S3 | none | 1 | Working liboqs/library build |
| T4 | ML-KEM handshake module | S1 (5) | S2 | T3 | 2-3 | Shared KEM module + tests |
| T5 | ML-DSA sign/verify | S1 (4) | S3 | T3 | 2-3 | Signing/verification module |
| T6 | Symmetric encryption (AEAD) | S1 (3) | S2 | T4 | 4 | Session encryption layer |
| T7 | ESP32 integration (incl. Week-1 test) | S1 (10) | S2 | T3, T4 | 1, 5-7 | ESP32 client + measurements |
| T8 | Device simulator and resource classes | S1 (5) | S2 | T4, T2 | 4-5 | Simulator (classical/hybrid/PQC profiles) |
| T9 | Gateway service | S2 (8) | S1 | T2, T4 | 3-5 | Gateway with sessions and forwarding |
| T10 | Cloud API/database | S2 (3) | S4 | T2 | 4 | Local API + DB |
| T11 | Policy schema | S2 (3) | S3 | T2 | 2 | Signed policy format and canonical encoding |
| T12 | Sensitivity classification | S2 (3) | S3 | T11 | 5 | Gateway-side flow -> level -> minimum mode |
| T13 | Capability registry | S2 (3) | S1 | T2 | 5 | Device profile store |
| T14 | Readiness rules | S2 (2) | S3 | T13 | 6 | Ready/Partial/Not Ready rules |
| T15 | Persistent policy-version storage | S2 (2) | S3 | T11 | 2-3 | Atomic highest-version store |
| T16 | Replay protection (incl. fast-forward bound) | S3 (4) | S2 | T5, T15 | 5 | Replay logic + tests |
| T17 | Downgrade rejection | S3 (3) | S2 | T12 | 5 | Downgrade logic + tests |
| T18 | Security-floor state machine + invariant monitor | S3 (10) | S2 | T1, T12 | 4-7 | State machine spec, code, invariant tests |
| T19 | Failure taxonomy | S3 (3) | S4 | T1 | 3-4 | Cause definitions and labels |
| T20 | Recovery controller (cause-specific, floor-bounded) | S3 (8) | S2 | T18, T19 | 7-9 | Controller + tests |
| T21 | Network fault injection | S4 (5) | S1 | T2 | 3-5 | netem scripts: burst loss, MTU, reorder, delay |
| T22a | Logging schema and log parser | S4 (3) | S2 | T2 | 2 | Schema + parser |
| T22b | Device logging hooks | S1 (2) | S4 | T22a | 6-7 | Device logs |
| T22c | Gateway audit logging and rate limiting | S2 (4) | S3 | T22a | 5-7 | Audit log + rate limiter |
| T23a | Static baselines (classical, hybrid, PQC, sensitivity-only) | S2 (3) | S4 | T9, T12 | 6 | Config-flag baselines |
| T23b | Adaptive baselines (downgrade-on-failure, static retry) | S2 (2) | S3 | T20 | 7 | Comparison baselines |
| T24 | ESP32 calibration and validation runs | S1 (5) | S4 | T7, T21 | 8-9 | Real-device data |
| T25 | Attack tests (invalid signature, modified/replayed policy, downgrade, fake handshakes) | S3 (5) | S1 | T16, T17 | 8-9 | Attack test report |
| T26 | State-machine model check (simplify-second) | S3 (2) | S4 | T18 | 9 | Model + result |
| T27 | Patent/invention-disclosure notes | S3 (2) | S4 | T20 | 10 | Notes for IP office |
| T28 | Experiment design and matrix | S4 (5) | S3 | T19, T22a | 3-5 | Design doc, matrix |
| T29 | Experiment runner and automation | S4 (6) | S2 | T21, T23a | 6-8 | Scripts |
| T30 | Data collection runs | S4 (6) | S1 | T29, T20 | 8-10 | Raw logs |
| T31 | Ground-truth labelling harness | S4 (2) | S3 | T19, T21 | 6 | Injected-cause labels |
| T32 | Data analysis (median, IQR, mean/SD, Wilson CI, confusion matrix, per-class P/R/F1) | S4 (6) | S3 | T30 | 10-11 | Cleaned data, stats |
| T33 | Graphs and tables | S4 (4) | S1 | T32 | 10-11 | Paper-ready figures |
| T34 | Paper sections | All (S1 4, S2 3, S3 5, S4 5) | swap | T32 | 10-12 | IEEE-style draft |
| T35 | PPT | S4 (3) | S2 | T34 | 12 | Slide deck |
| T36 | Demo | S2 (2) | S1 | T38 | 11-12 | Demo script and rehearsal |
| T37 | Viva question bank | S4 (3) | all (S1 3, S2 2, S3 2) | T34 | 12-13 | Question bank |
| T38 | Final integration and Docker | S2 (5) | S1 | T20, T22c | 9-11 | One-command system |

Hours per student sum to 48 (S1: T3 4, T4 5, T5 4, T6 3, T7 10, T8 5, T22b 2, T24 5, paper 4, viva 3, known-answer tests 3; S2: T2 3, T9 8, T10 3, T11 3, T12 3, T13 3, T14 2, T15 2, T22c 4, T23a 3, T23b 2, T38 5, T36 2, paper 3, viva 2; S3: T1 4, T16 4, T17 3, T18 10, T19 3, T20 8, T25 5, T26 2, T27 2, paper 5, viva 2; S4: T21 5, T22a 3, T28 5, T29 6, T30 6, T31 2, T32 6, T33 4, paper 5, T35 3, T37 3).

---

## 4. RACI (R = does, A = accountable, C = consulted, I = informed)

| Major task | S1 | S2 | S3 | S4 |
|-----------|----|----|----|----|
| Threat model | C | C | R/A | I |
| Architecture | C | R/A | C | I |
| Crypto integration | R/A | C | C | I |
| ESP32 | R/A | C | I | C |
| Policy schema and sensitivity | C | R/A | C | I |
| Gateway and cloud | C | R/A | C | I |
| State machine | I | C | R/A | I |
| Recovery controller | I | C | R/A | C |
| Replay and downgrade | C | C | R/A | I |
| Fault injection | C | I | C | R/A |
| Experiments and analysis | C | C | C | R/A |
| Paper | R | R | R | A (editor) |
| PPT and demo | C | R/A demo | C | R/A PPT |
| Invention notes | I | I | R/A | C |

---

## 5. 13-week schedule

| Week | S1 | S2 | S3 | S4 |
|------|----|----|----|----|
| 1 | T3; Week-1 ESP32 test | T2 | T1 | T22a (schema); T28 draft |
| 2 | T4, T5 | T11, T15 | T1 final; T19 draft | T21 start |
| 3 | T4, T5 finish | T9 | T19; T18 spec | T21; T28 |
| 4 | T6; T8 | T9; T10 | T18 build | T28 matrix final |
| 5 | T8; T7 | T9; T12; T13; T22c | T16; T17 | T21 finish |
| 6 | T7; T22b | T14; T23a; T22c | T18 complete | T29; T31 |
| 7 | T7; T22b | T23b; T22c | T20 | T29; pilot runs |
| 8 | T24 | T38 | T20; T25 | T30 (full runs start) |
| 9 | T24 | T38 | T25; T26 | T30 |
| 10 | Paper | T38; T36 | T27; paper | T32; T33 |
| 11 | Reruns/fixes | T36 rehearsal | Paper | T32; T33; results |
| 12 | Viva prep | Viva prep | Viva prep | T35; T37 |
| 13 | Buffer | Buffer | Buffer | Buffer, final submission |

**Gates:**
- End of Week 1: go/no-go on crypto library and ESP32 route. Decide whether compute-failure classification stays.
- End of Week 7: compute-failure decision using Week-1 and pilot data.
- End of Week 9: feature freeze. After this only bug fixes.

---

## 6. Weekly meeting structure

| Session | Focus | Use |
|---------|-------|-----|
| 1 (2 h) | Technical implementation | Pair on hard parts; review interfaces |
| 2 (2 h) | Integration and debugging | Merge branches; end-to-end tests; fix mismatches |
| 3 (2 h) | Testing, documentation, review | Run tests; update docs; review against definitions of done |

Keep a shared task board, one branch per component, and a 15-minute status round at the start of Session 1.

---

## 7. Integration dependencies

1. Interface spec (T2) blocks gateway, device and logging work.
2. Crypto module (T3-T5) blocks handshake, signed policy and ESP32.
3. Policy schema (T11) blocks sensitivity, version store and replay.
4. State machine (T18) and failure taxonomy (T19) block the recovery controller (T20).
5. Log schema (T22a) blocks all logging hooks and analysis.
6. Fault injection (T21) and labels (T31) block experiments.
7. Recovery controller blocks adaptive baselines, full runs and the demo.

---

## 8. Definition of done for major components

- **Crypto module:** round-trip and known-answer tests pass; ML-DSA verification rejects tampered policy.
- **Gateway:** accepts sessions, verifies policy before use, enforces floors, forwards to cloud.
- **Policy engine:** rejects invalid, stale, replayed and untrusted-authority policies.
- **State machine:** no reachable state activates a flow below its floor; invariant tests pass.
- **Recovery controller:** each cause maps to an allowed action set; security failures are rejected and logged; no action lowers the floor.
- **Failure classifier:** reports a confusion matrix against injected ground truth.
- **Experiments:** every scenario in the matrix has data and a stated repetition count.
- **Paper:** methodology, results and limitations match the data; claims match the honest novelty statement.

---

## 9. Risk register

| Risk | Warning sign | Fallback | Owner |
|------|--------------|----------|-------|
| PQC library failure | Build fails by end of Week 1 | Switch library or use OpenSSL provider | S1 |
| ESP32 integration failure | No handshake by Week 5 | Route B: ESP32 measures primitives only; simulate device | S1 |
| DTLS/protocol integration failure | Handshake fails on the chosen stack | Simplified authenticated prototype, clearly labelled as such | S1 |
| Gateway/device interface mismatch | Failures at Week 3-4 integration | Freeze interface spec; mock messages for testing | S2 |
| Failure causes not distinguishable | Classifier confusion above threshold | Report the result honestly; merge classes | S3 |
| Compute failures not observed | Week-1 and pilot data show none | Drop compute class; keep loss/MTU/security | S3/S4 |
| Network emulation problems | netem does not affect ESP32 path | Emulate in-process; validate a subset on hardware | S4 |
| Insufficient data | Fewer than 100 handshakes per cell | Reduce factor levels, not repetitions | S4 |
| Student unavailability | Missed sessions | Use backup owners; shrink cut list | Team |
| Scope creep | New module proposed | Reject unless it replaces a cut item | Team |
| Prior-art conflict | Mentor/IP office finds closer art | Reposition contribution to floor-bounded recovery | S3 |

---

## 10. Cut list

- **Cut first:** flooding evaluation, readiness scoring extras, model check, extra baseline ablations.
- **Simplify second:** ESP32 scenarios (fewer than the emulated set), cloud UI, fast-forward protection details, adaptive baselines.
- **Never cut:** signed policy verification, replay and downgrade rejection, security-floor state machine, cause-classified recovery, five core baselines, ESP32 calibration data, logging and analysis, honest limitations.

---

## 11. Approval rules

| Change | Proposed by | Approved by |
|--------|-------------|-------------|
| Cryptographic (algorithm, parameter, library) | S1 | S3 review, then mentor |
| Policy schema or rules | S2 | S3 |
| State-machine transitions or invariants | S3 | S2 review, invariant tests must pass |
| Experiment matrix or metrics | S4 | S3; frozen after Week 9 except by team decision |
| Any public paper, preprint, public repository or patent step | any | Mentor, all four students and the institution's IP office; nothing public before the disclosure decision |

---

## 12. How the four roles combine

S1 provides trustworthy cryptographic primitives and a real constrained device, S2 builds the gateway, cloud and registry that carry signed policy and traffic, and S3 turns that policy into an enforced security floor with cause-aware recovery that can never lower it. S4 makes the system measurable: fault injection, logs, baselines, statistics and graphs turn the mechanism into evidence, which is what makes the work a paper and not just a prototype. Every claim in the report and paper is owned by at least two people, so any student can answer viva questions on the whole design.
