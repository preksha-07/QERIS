# QERIS Viva Question Bank (Task T37)

**Owner:** S4 (prepared; reviewed by component owners)
**Coverage:** All four components — each student must be able to answer any question
**Format:** Question → Model Answer → Owner (who is primary on this topic)

---

## Part A — Cryptography and Device Layer (S1)

**Q-A1. What is ML-KEM-512 and why was it chosen?**
ML-KEM-512 is the FIPS 203 standardised Key Encapsulation Mechanism at NIST Security Level 1, based on the Module Learning With Errors (MLWE) problem. It was chosen because it is NIST-standardised, available in `liboqs 0.16`, produces a 768 B ciphertext (compact relative to other Level 1 candidates), and runs on the ESP32 within an acceptable key-generation time for emulation. The 512 variant was preferred over 768/1024 for ESP32 compatibility.
*Owner: S1*

**Q-A2. Why do you use HKDF-SHA-256 after ML-KEM rather than using the ML-KEM shared secret directly as a session key?**
The ML-KEM shared secret is a uniform random 32-byte value, but it is bound only to the KEM context. HKDF-SHA-256 mixes in the session context (device_id, flow_id, sensitivity_tier, policy_version) to produce a key that is cryptographically bound to the authorised session parameters. This prevents key reuse across sessions and ensures that a key derived for a LOW-sensitivity flow cannot be used on a CRITICAL flow even if the raw shared secret were compromised.
*Owner: S1*

**Q-A3. What is ML-DSA and what does it protect in QERIS?**
ML-DSA (FIPS 204, based on CRYSTALS-Dilithium) is a lattice-based digital signature scheme. In QERIS it signs the policy envelope (flow_id, sensitivity, minimum_mode, policy_version, authority_id). The gateway verifies this signature before using the policy to make any admission decision. A forged or tampered policy is rejected even if the cryptographic handshake succeeds — a valid KEM operation is not authorisation.
*Owner: S1 / S3*

**Q-A4. What does the ESP32 calibration data actually give you, and why is one real device a threat to validity?**
S1 ran ML-KEM-512 keypair generation, encapsulation, and decapsulation on the real ESP32-WROOM-32 and recorded wall-clock time and stack usage. These measurements anchor the simulator's Gaussian latency model (mean and standard deviation). The threat to validity is that the ESP32 is one specific silicon implementation with one SDK version; other constrained devices (nRF9160, CC2652, RISC-V MCUs) have different instruction sets, FPU characteristics, and clock speeds. The emulated `edge_gateway` and `standard_compute` classes are calibrated to the ESP32 but are not hardware-validated.
*Owner: S1 / S4*

**Q-A5. Why is a successful ML-KEM operation not device authentication?**
ML-KEM proves that the holder of the private key decapsulated the ciphertext correctly. It does not prove identity unless the public key is certified to a registered device ID. In QERIS the device registry (S2 `devices.json`) maps device IDs to capability profiles, but there is no X.509-style certificate binding the ML-KEM public key to a device ID. Device authentication is explicitly labelled `NOT_IMPLEMENTED` in the S1 device simulator and is a known open problem.
*Owner: S1*

---

## Part B — Gateway, Cloud and Policy (S2)

**Q-B1. What is a "security floor" and where is it stored?**
The security floor is the `minimum_mode` field in the signed policy JSON for each flow — the weakest cryptographic mode the gateway will accept on that flow. It is stored in `policy.json`, loaded at gateway start, and its integrity is guaranteed by ML-DSA signature verification (S3 audit hook). The gateway also maintains a persistent version store to prevent rollback to an older (possibly weaker-floor) policy.
*Owner: S2 / S3*

**Q-B2. How does the gateway decide whether to ALLOW, REJECT, or FLOOR_UNREACHABLE?**
Three sequential checks: (1) Is the flow_id known? If not → REJECT (unknown flow). (2) Can the device's highest supported mode ever satisfy the floor? If not → FLOOR_UNREACHABLE (structural mismatch; no retry). (3) Is the requested mode ≥ the floor AND supported by the device? If yes → ALLOW, else → REJECT (policy or capability violation). The S3 hook then independently verifies authority, replay state, and downgrade before the decision is finalised.
*Owner: S2 / S3*

**Q-B3. What are the seven baselines and why were they chosen?**
B1–B3 (Static Classical/Hybrid/PQC) are fixed-mode references representing a system with no dynamic negotiation. B4 (Sensitivity-Only) adds sensitivity-aware mode selection but no recovery. B5 (Downgrade-on-Failure) is the naive industry fallback — included to characterise the *threat* of floor violation. B6 (Static Retry with Floor) is the obvious hardening of B5 but without cause awareness. B7 (QERIS Full Gateway) is our contribution. Together they span the design space from completely static to fully adaptive, isolating the marginal benefit of each feature.
*Owner: S2 / S4*

**Q-B4. What happens if a policy update arrives during an active session?**
The gateway's persistent version store (S2 T15) maintains the highest seen version. Any policy with version ≤ highest is rejected as a replay or rollback by the S3 replay protection (T16). If a newer version arrives while a session is active, the existing session continues under the old policy (session keys are already derived) and the next handshake picks up the new policy. Policy-update-during-session is a documented scenario in the experiment matrix.
*Owner: S2*

**Q-B5. Why does QERIS use a signed policy rather than a configuration file?**
A configuration file can be tampered by a compromised gateway process, a rogue administrator, or an attacker with file-system access. A signed policy (ML-DSA signature verified by S3 against a pinned authority key) provides a cryptographic chain: even if the gateway is partially compromised, it cannot lower a flow's security floor without forging the ML-DSA signature. This is the "policy integrity" threat model requirement T1 addressed by S3.
*Owner: S2 / S3*

---

## Part C — Security Logic and Recovery (S3)

**Q-C1. State the floor-bounded recovery invariant formally.**
∀ recovery action *a* selected by the `RecoveryController`: `MODE_RANK(mode_after(a)) ≥ MODE_RANK(policy_floor)`. Every candidate action is checked against the floor before being returned. If no candidate action keeps the mode at or above the floor, the controller returns `FLOOR_UNREACHABLE` (verdict) and closes the session — it never downgrades.
*Owner: S3*

**Q-C2. What are the four cause classes and what recovery action is permitted for each?**

| Cause | Action | Rationale |
|---|---|---|
| `LOSS_TIMEOUT` | Bounded exponential-backoff retry at same mode | No security information in the failure; retrying is safe |
| `MTU_FRAGMENT` | Reduce fragment size, retry at same mode | Fragment size adjustment has no security implication |
| `COMPUTE` | Extend timeout budget, retry (if class observed) | Device is slow, not compromised |
| `SECURITY_FAILURE` | `DISCARD_AND_LOG`, quarantine — **no retry, no mode change** | A security failure is never transient; retrying enables oracle attacks |

*Owner: S3*

**Q-C3. What is the priority order of cause classification and why?**
`SECURITY_FAILURE` > `MTU_FRAGMENT` > `LOSS_TIMEOUT` > `COMPUTE`. Security failure is checked first because a packet that fails authentication AND arrived late is a security event, not a latency event. Misclassifying a security failure as a transport fault and retrying is a protocol-level vulnerability.
*Owner: S3*

**Q-C4. How does replay protection work and what is the fast-forward bound?**
The version store records the highest policy version ever successfully verified. Any incoming policy with version ≤ that value is rejected as a replay or rollback. The fast-forward bound (`max_version_jump`, typically 100) rejects policy versions that jump too far ahead, preventing an attacker from pre-positioning a very high version number to permanently lock out legitimate policy updates.
*Owner: S3*

**Q-C5. What does the invariant monitor check and when does it fire?**
The `InvariantMonitor` in `floor_state_machine.py` checks seven invariants after every state transition: (I1) no flow activates below its floor; (I2) security failures never trigger a retry; (I3) the floor can only increase over a session; (I4) FLOOR_UNREACHABLE is terminal; (I5) downgrade attempts are always logged; (I6) quarantined sessions do not resume; (I7) policy replay increments a counter and closes the session. If any invariant is violated it raises `InvariantViolation` immediately — the test suite has 62 invariant tests covering all seven.
*Owner: S3*

**Q-C6. Why does QERIS never retry a security failure, even when the security failure could be a transient bit error?**
This is a deliberate, conservative design choice rooted in threat model T48: classification is determined by the verification result, not by timing alone. An AEAD tag verification failure or ML-DSA signature failure cannot be explained by a bit flip in transport — both checks operate over the complete authenticated data and use cryptographically strong MAC/signature algorithms. Retrying a bad-signature event would give an attacker an oracle for crafting valid signatures one retry at a time. The paper explicitly notes this as a design trade-off, not an oversight.
*Owner: S3*

---

## Part D — Data Science and Evaluation (S4)

**Q-D1. Why do you use Wilson score intervals rather than normal-approximation confidence intervals for success rates?**
The normal approximation (Wald interval) is unreliable when the true probability is near 0 or 1, or when the sample size is small. In our experiment, Static PQC achieves 0% success in MTU scenarios (proportion = 0/N); the Wald interval would report [0%, 0%] which gives a misleadingly precise zero. The Wilson interval correctly reports a non-zero upper bound (e.g., [0.0%, 0.3%]) that honestly reflects residual uncertainty. The Wilson interval is also coverage-accurate for proportions across the full [0,1] range without requiring a normal approximation.
*Owner: S4*

**Q-D2. You report median and IQR for latency rather than mean and standard deviation. Why?**
PQC handshake latency has a right-skewed distribution — most handshakes complete near the mode but rare key-generation outliers or GC pauses produce a heavy right tail. The median is more robust to outliers than the mean; the IQR gives the spread of the central 50% without being inflated by extreme values. We report mean and SD as supplementary statistics where the distribution is approximately unimodal (CLASSICAL and HYBRID). The S4 spec explicitly requires this: *"Report median and IQR for latency. Mean and SD where the distribution justifies it."*
*Owner: S4*

**Q-D3. How do you avoid making unsupported causal claims?**
Causal claims require controlled ablation comparisons where a single variable changes between conditions. For example, the claim "cause-aware recovery increases handshake success vs static retry" is supported by comparing B6 (Static Retry, no cause awareness) and B7 (QERIS, cause-aware) under identical fault conditions. The claim "downgrade-on-failure is insecure" is supported by the floor violation metric — 40% violations vs 0% for QERIS — which is directly observable, not inferred. We do not claim that higher classifier F1 causes higher success rate (that is correlation); we show the floor invariant holds independently of classifier accuracy through the invariant audit.
*Owner: S4*

**Q-D4. The `mtu_fragment` classifier class has F1 = 0.000. Doesn't that break your evaluation?**
No, for two reasons. First, the MTU-fragment *recovery action* (adaptive re-fragmentation) is reachable via the `loss_timeout` code path in the current build — the gateway refragments on any repeated transmission failure, regardless of the classified cause. So the recovery outcome is correct even when the cause label is wrong. Second, the floor-invariant audit operates on the outcome column (`outcome`), not on the cause label. The 0.000 F1 is a known limitation of the emulated signal path (no IP-layer fragmentation counters) and is documented in Section 7 (Limitations). A real deployment would instrument the IP stack.
*Owner: S4 / S3*

**Q-D5. What is the Gilbert-Elliott model and why did you use it for burst loss?**
The Gilbert-Elliott (GE) model is a two-state Markov chain representing a channel that alternates between a "Good" state (low loss probability) and a "Bad" state (high loss probability). It captures the burst correlation typical of real wireless channels where packet loss clusters in time — a packet lost tends to be followed by more lost packets. Simple uniform (Bernoulli) loss doesn't reproduce this clustering. We use GE parameters (p=8%, r=35%, loss_prob_B=85%) calibrated to match typical 802.11 interference patterns in the frequency band used by the ESP32.
*Owner: S4*

**Q-D6. How do you ensure that raw logs are never modified after collection?**
The `ExperimentRunner` opens the output file in write mode at the start of each run and closes it at the end. Every record is appended sequentially. The runner never opens the file in append mode after the run closes. The run directory includes a `run_metadata.json` with creation timestamp. All analysis reads only from the raw file; transformed datasets are written to a separate `data/processed/` path (reserved for future use). The S4 spec states: *"Never edit raw logs by hand."*
*Owner: S4*

**Q-D7. One ESP32 is a "threat to validity." What would you need to remove that threat?**
Three things: (1) Repeat the hardware validation runs with at least three physically distinct ESP32 boards to quantify inter-board variance. (2) Validate at least one additional constrained device family (e.g., nRF9160 or STM32WL) to test whether the calibration generalises beyond the Xtensa LX6. (3) Run a subset of the full experiment matrix on real hardware rather than the in-process simulator and report the delta. The S4 spec acknowledges this and places it on the cut list as "one real device class — a limitation to state honestly."
*Owner: S4 / S1*

---

## Part E — Cross-Component and System-Level Questions

**Q-E1. Can the system be fooled by an attacker who simultaneously injects network loss and replays a policy?**
No. The S3 classifier prioritises `SECURITY_FAILURE` over `LOSS_TIMEOUT`. If replay protection detects a stale version, the event is classified as `SECURITY_FAILURE` even if network loss signals are also present. The `RecoveryController` immediately calls `DISCARD_AND_LOG` — no retry is attempted — so the attacker gains nothing from the concurrent loss injection.
*Owner: S3 / S4*

**Q-E2. What happens if two simultaneous handshakes share the same session key derivation context?**
The context info for HKDF is `(device_id, flow_id, sensitivity_tier, policy_version)`. If two concurrent handshakes share all four values (same device, same flow, same policy), they would derive the same session key — a nonce collision risk under AES-GCM. The S1 `MessageEncryptor` enforces a strictly incrementing per-message counter, but concurrent sessions with the same key would interleave nonces dangerously. In the current build, sessions are not concurrent per device; a production build would add a session_id or a random nonce component to the HKDF info string.
*Owner: S1 / S3*

**Q-E3. How does the system handle a device that reports CLASSICAL as its highest supported mode when the policy floor is PQC?**
`check_floor_feasibility()` in the S2 gateway detects this before any handshake is attempted and returns `FLOOR_UNREACHABLE`. The S3 hook propagates this as a terminal `FLOOR_UNREACHABLE` verdict. No retry is issued because the structural constraint cannot be resolved by retrying — the device hardware cannot be upgraded by the gateway. The scenario `floor_unreachable_classical_device_on_critical_flow` in the experiment matrix tests this exact case.
*Owner: S2 / S3 / S4*

**Q-E4. Why does Static PQC achieve 0% success in your experiment?**
Static PQC always uses ML-KEM-512, which produces a public key of 800 B and a ciphertext of 768 B. Combined into a single TLS-style record, the handshake exchange exceeds 1820 B — larger than all three tested path MTU levels (1500, 1280, 576 B) in the MTU-constrained scenarios. Without adaptive re-fragmentation, the oversized record is detected as an MTU violation and the transmission fails. QERIS detects this cause and reduces the fragment size dynamically; Static PQC has no such mechanism.
*Owner: S2 / S4*

**Q-E5. What would a null result look like and what would it mean?**
A null result would mean QERIS Full Gateway achieves the same or lower success rate as the best non-cause-aware baseline (e.g., Static Retry) while maintaining the floor invariant. That would suggest cause classification does not improve recovery — the system would still be correct (floor preserved) but not useful. We would report that finding honestly, remove the "cause-aware recovery improves reliability" claim, and retain the "floor-bounded recovery never violates the signed floor" contribution (which is independently verifiable regardless of success rates). The S4 spec explicitly says: *"Report failures too."*
*Owner: S4*

**Q-E6. Why did you not measure compute failures (the `COMPUTE` cause class)?**
The `COMPUTE` cause class is conditional in the S3 spec: include it only if resource exhaustion signals are observed in pilot data. In our pilot and full runs, no handshakes produced response delays exceeding the compute-delay threshold — the ESP32 key-generation time is captured in the `TIMEOUT` path but never isolated as compute-specific. This matches the expected outcome on a lightly loaded testbed. The compute class is excluded from the matrix (as the spec permits) and the paper explicitly states why.
*Owner: S3 / S4*

---

## Quick Reference — Most Likely Viva Questions

| # | Question | Owner | Critical? |
|---|---|---|---|
| 1 | State the floor-bounded invariant | S3 | ★★★ |
| 2 | Why zero retries on security failure? | S3 | ★★★ |
| 3 | Why Wilson CI not Wald? | S4 | ★★ |
| 4 | One ESP32 — how does that limit your conclusions? | S4 | ★★ |
| 5 | What is ML-KEM and why ML-KEM-512? | S1 | ★★★ |
| 6 | Why does Static PQC achieve 0%? | S4 | ★★ |
| 7 | What does the confusion matrix show about the classifier? | S4 | ★★ |
| 8 | How does replay protection work? | S3 | ★★ |
| 9 | Why signed policy not config file? | S2 / S3 | ★★ |
| 10 | How is the floor invariant formally tested? | S3 | ★★★ |
| 11 | What would a null result mean? | S4 | ★★ |
| 12 | Downgrade-on-Failure is more "available" — isn't that better? | S4 | ★★★ |

**Answer to Q12 (critical):** Availability that is achieved by operating below the signed security floor is not legitimate availability — it is a security policy violation. A CRITICAL-sensitivity flow (e.g., emergency stop signal, patient monitoring) that operates at CLASSICAL strength offers no post-quantum protection. The Downgrade-on-Failure baseline's "availability" numbers must be discounted because 40% of its "successful" handshakes are, by definition, non-compliant. QERIS achieves 59.5% *genuinely secure* availability — every one of those handshakes operates at or above the signed floor.
