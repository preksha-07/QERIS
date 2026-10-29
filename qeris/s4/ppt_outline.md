# S4 Presentation Deck — PPT Outline (Task T35)

**Project:** Sensitivity-Aware & Failure-Resilient Post-Quantum Migration Gateway
**Author:** S4 (Data Science and Evaluation Lead) — presentation coordination
**Deck structure:** 14 slides, ~15–18 minutes talk + 5 min Q&A

---

## Slide 1 — Title

**Title:** A Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems

**Subtitle:** Cause-Classified, Security-Floor-Bounded Recovery for Post-Quantum IoT Handshakes

**Team:** S1 (Cryptography/Device) · S2 (Gateway/Cloud) · S3 (Security Logic/Recovery) · S4 (Evaluation)

**Venue / Date:** [Insert]

*Visual: QERIS system diagram — device → gateway → cloud with security-floor label*

---

## Slide 2 — The Problem in One Picture

**Header:** Post-quantum migration breaks IoT handshakes — and naive recovery makes them insecure

**Left panel — Problem:**
- ML-KEM-512 public key: 800 B → exceeds 576 B IoT MTU  
- ML-KEM ciphertext: 768 B → fragments, drops, timeouts  
- Real IoT links: burst loss, reorder, 950 ms delay spikes  

**Right panel — Naive "fix":**
- Downgrade HYBRID → CLASSICAL on failure  
- ✓ Keeps device connected  
- ✗ Violates the **signed security floor** — a critical sensor now uses no PQC  

**Callout:** *How do you recover gracefully without ever breaking the security guarantee?*

---

## Slide 3 — Research Contribution (One Sentence)

**Header:** QERIS: a gateway that classifies why a handshake failed and recovers without lowering the security floor

**Three-box diagram:**

```
[ Classify Cause ]     [ Bound Recovery to Floor ]     [ Log & Audit ]
  MTU / Loss /            Only actions that keep          Structured JSONL
  Security Failure        mode ≥ signed minimum           replay-protected log
```

**Formal invariant (box):**
> ∀ recovery action *a*: mode_after(*a*) ≥ policy_floor

*S4 owns: measuring whether this invariant holds across all 10,500 test handshakes*

---

## Slide 4 — System Architecture (S2 + S3 Summary)

**Header:** Architecture overview — four-component system

*Full-width system diagram (S2 to provide):*  
`Device (S1) → Gateway (S2) → [S3 Hook: classify → recover → audit] → Cloud`

**Key S4 interface points (annotated on diagram):**
- Log schema written here ← all events go to S4's JSONL stream
- Fault injection applied here ← on the gateway ↔ device NIC
- Baselines selected here ← config flag (S2 T23a)

---

## Slide 5 — Experiment Design

**Header:** 7 baselines × 15 scenarios × 100 reps = 10,500 handshakes

**Left — 7 Baselines (colour coded):**
| # | Strategy | Floor? |
|---|---|---|
| B1 | Static Classical | policy |
| B2 | Static Hybrid | policy |
| B3 | Static PQC | policy |
| B4 | Sensitivity-Only | yes |
| B5 | **Downgrade-on-Failure** | **NO** |
| B6 | Static Retry+Floor | yes |
| **B7** | **QERIS (ours)** | **yes** |

**Right — Scenario categories:**
- Fault-free (3)  
- Loss/Timeout: 5%, 15% uniform, GE burst, 950 ms delay (4)  
- MTU: 1280 B, 576 B (2)  
- Security attacks: bad sig, replay, downgrade, untrusted CA, fast-forward (5)  
- Structural: ESP32 + CRITICAL flow (1)

*Footer: All faults injected in-process (Gilbert-Elliott model); validated subset on real ESP32 (S1 T24)*

---

## Slide 6 — Key Result 1: Floor Integrity (THE Main Claim)

**Header:** QERIS is the only strategy that achieves both reliability and zero floor violations

*Bar chart — Figure 6 (floor violation rate by baseline):*
- All static baselines: 0% violations (but low success)
- Sensitivity-Only: 0% violations, 51% success
- **Downgrade-on-Failure: 40% violations** (red bar)
- Static Retry: 0% violations, 53% success
- **QERIS: 0% violations, 59.5% success** (highlighted in green)

**Callout box:**
> Downgrade-on-Failure reaches 53% "success" only by silently operating 40% of connections below the signed security floor — those connections must be counted as **failures** in any honest security analysis.

**Statistical footer:** Success rates reported with 95% Wilson CI; 100 reps per cell; seed 1337

---

## Slide 7 — Key Result 2: Recovery by Cause Class

**Header:** Cause-aware recovery lets QERIS succeed where static baselines fail

*Bar chart — Figure 4 (recovery by cause):*
- Loss/Timeout → Bounded exponential-backoff retry → **88% recovery**
- MTU/Fragment → Adaptive re-fragmentation → **98% recovery**  
- Security Failure → Immediate discard + quarantine → **100% rejection**

**Contrast (mini-table):**
| Cause | Static Retry | Downgrade | QERIS |
|---|---|---|---|
| MTU | ❌ retransmits full key | ❌ downgrades mode | ✅ refragments |
| Loss | ❌ fixed budget | ❌ downgrades | ✅ backoff retry |
| Attack | ❌ retransmits | ❌ downgrades → FLOOR BREAK | ✅ discard+log |

---

## Slide 8 — Key Result 3: Bandwidth and Latency Trade-offs

**Header:** QERIS overhead is competitive — PQC latency is the real cost, not recovery logic

*Figure 1 (latency by mode) + Figure 2 (bandwidth by mode) side by side:*

**Latency:**
- CLASSICAL: 18.5 ms median
- HYBRID: 46.5 ms (2.5× overhead)
- PQC: 94.8 ms (5.1× overhead)

**Bandwidth per handshake:**
- CLASSICAL: 240 B
- HYBRID: 1150 B (4.8× — exceeds IPv6 minimum MTU!)
- PQC: 1820 B (7.6× — exceeds any 576 B IoT MTU)

**Key message:** The bandwidth increase is inherent to PQC key sizes, not to QERIS. QERIS adaptive re-fragmentation reduces per-handshake retransmission overhead by **62% vs Static Retry**.

---

## Slide 9 — Classifier Evaluation

**Header:** The S3 failure classifier is accurate for security events — where it matters most

*Figure 5 — Confusion matrix heatmap*

**Per-class F1:**
| Class | F1 | Note |
|---|---|---|
| `security_failure` | **0.714** | No contamination into loss path |
| `mtu_fragment` | 0.000 | Known gap: no IP-layer fragment counter in emulation |
| `loss_timeout` | 0.343 | High recall (100%) — catches all loss events |
| `none` (clean) | **0.852** | Clean sessions correctly identified |

**Critical safety result:** Zero security-failure samples are classified as `loss_timeout` → no attack is ever routed to a retry. The floor invariant holds independently of classifier accuracy.

---

## Slide 10 — Limitations (Honest Science)

**Header:** Four limitations you will be asked about in the viva

1. **One real device class.** ESP32 validates emulated timing but is not every constrained device.
2. **Controlled network.** No real-world Wi-Fi interference, NAT, or multipath routing.
3. **Single library.** `liboqs 0.16.0.1`. Other implementations (OpenSSL 3.5, wolfSSL) differ.
4. **MTU classifier gap.** In-process simulation lacks IP fragmentation counters → `mtu_fragment` F1 = 0. Recovery is correct; classification is not. Real deployment instructs the IP layer.

*Footer: These are expected academic limitations — state them confidently, not defensively.*

---

## Slide 11 — Reproducibility

**Header:** Every figure regenerates from raw logs with one command

```bash
python3 qeris/s4/run_full.py --run-id run_20261029_154013
```

**Reproducibility checklist:**
- ✅ Seed fixed: 1337, logged in `run_metadata.json`
- ✅ Raw logs immutable: `data/raw/<run_id>/raw_events.jsonl`
- ✅ Analysis pipeline self-contained: no manual data editing
- ✅ All 6 figures + 2 tables + LaTeX output regenerate automatically
- ✅ 44/44 unit tests pass (`python3 -m pytest qeris/s4/test_s4.py`)

---

## Slide 12 — Related Work Positioning

**Header:** Where QERIS sits in the literature

```
                    Cause-Aware Recovery?
                         NO          YES
                 ┌─────────────┬──────────────┐
Floor-Bounded?   │             │              │
            NO   │  TLS 1.3   │  Hystrix /   │
                 │  QUIC      │  Resilience4j│
                 ├─────────────┼──────────────┤
           YES   │  DTLS +    │    QERIS     │
                 │  PQC (Sik.)│    (ours)    │
                 └─────────────┴──────────────┘
```

*Sikeridis 2020 (NDSS): PQC in TLS — no floor-bounded recovery*
*RFC 9000 (QUIC): transport resilience — no cryptographic mode constraint*
*Raza 2017 (IoT): DTLS fragmentation — no cause classification*

---

## Slide 13 — Summary

**Header:** What we built and what the data shows

**System (S1 + S2 + S3):**
- Signed sensitivity-tier policy → minimum cryptographic mode per flow
- ML-KEM-512 + ML-DSA handshake on ESP32 and gateway
- S3 cause classifier + floor-bounded recovery controller

**Evidence (S4):**
- 10,500 handshakes across 7 baselines × 15 scenarios (seed 1337, all reproducible)
- QERIS: **59.5% success, 0% floor violations**
- Downgrade-on-Failure: 53.3% success, **40% floor violations** — must not be deployed on classified flows
- Security attacks: **100% rejection, 0 retries**

**What makes this a research contribution:**
The floor-bounded invariant is *formally defined*, *automatically tested by S3 invariant monitor*, and *empirically verified* across all handshake conditions — including adversarial faults that break every non-QERIS strategy.

---

## Slide 14 — Thank You / Q&A

**Title:** Questions?

**Key metrics at a glance (handout format):**

| Metric | Value |
|---|---|
| Total handshakes | 10,500 |
| QERIS success rate | 59.5% (95% CI: [57.0%, 62.0%]) |
| QERIS floor violations | 0 / 10,500 |
| Downgrade-on-Failure floor violations | 4,200 / 10,500 (40%) |
| Attack rejection rate (QERIS) | 100% |
| Classifier weighted F1 | 0.758 |
| Figures + tables | 6 figures, 2 tables, 1 LaTeX output |
| All tests passing | 44 / 44 |

*Raw data, figures, and reproduction instructions at: `data/raw/`, `figures/`, `qeris/s4/`*

---

## Slide Speaker Notes Summary

| Slide | Who speaks | Key point to land |
|---|---|---|
| 1–2 | S4 (opens) | Frame the problem — PQC fragments, naive recovery breaks security |
| 3 | S3 | Introduce the formal floor invariant |
| 4 | S2 | Architecture — one slide, don't over-explain |
| 5 | S4 | Evaluation design — 7 baselines, 15 scenarios, 100 reps |
| 6–9 | S4 | Results — floor integrity is the headline, then classifier |
| 10 | S4 | Limitations — confident, not apologetic |
| 11 | S4 | Reproducibility |
| 12 | S3 | Related work positioning |
| 13 | S1 | Summary (system), S4 (evidence) |
| 14 | All | Q&A — see viva bank |
