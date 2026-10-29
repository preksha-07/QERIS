# S1 - Cryptography and Device Engineer (48 hours)

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway
**Contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes
**Teammates:** S2 (gateway/cloud), S3 (state machine/recovery), S4 (data science)

## 1. Your mission
Provide trustworthy cryptographic building blocks and the one real constrained device (ESP32). Everything the gateway trusts (signed policy, session keys, encrypted payloads) rests on your work being correct.

## 2. Responsibilities
**Primary:** crypto library setup, ML-KEM, ML-DSA, AEAD session layer, ESP32 integration, device simulator with device profiles and resource classes, device logging hooks, ESP32 calibration runs.
**Secondary:** known-answer tests and key-handling review, crypto/device paper sections, viva prep.
**Backup for:** ML-DSA signing shared with S3; gateway service (S2's critical task); replay logic (S3).

## 3. Tasks

| ID | Task | Hours | Weeks | Depends on | Deliverable |
|----|------|-------|-------|------------|-------------|
| T3 | Crypto library setup (liboqs or OpenSSL 3.5) | 4 | 1 | none | Working build on laptop/gateway |
| T7 | ESP32 integration, incl. Week-1 test | 10 | 1, 5-7 | T3, T4 | ESP32 client + measurements |
| T4 | ML-KEM handshake module (shared by device and gateway) | 5 | 2-3 | T3 | KEM module + tests |
| T5 | ML-DSA sign/verify | 4 | 2-3 | T3 | Signing and verification module |
| T6 | AEAD session layer (AES-GCM or ChaCha20-Poly1305) | 3 | 4 | T4 | Session encryption |
| T8 | Device simulator: Classical/Hybrid/PQC profiles, CPU and memory classes | 5 | 4-5 | T4, T2 | Simulator |
| - | Known-answer and round-trip tests, key-handling review | 3 | 3, 7 | T4, T5 | Test suite |
| T22b | Device logging hooks (per S4 schema) | 2 | 6-7 | T22a | Device logs |
| T24 | ESP32 calibration and validation runs | 5 | 8-9 | T7, T21 | Real-device data |
| T34 | Crypto and device paper sections | 4 | 8-10 | T24 | Draft text |
| T37 | Viva prep | 3 | 11-13 | T34 | Q&A notes |

## 4. Weekly plan

| Week | Hours | Work |
|------|-------|------|
| 1 | 6 | T3 library; Week-1 ESP32 test (see section 5) |
| 2 | 5 | T4 KEM (3h); T5 signing (2h) |
| 3 | 5 | T4 finish (2h); T5 finish (2h); tests (1h) |
| 4 | 5 | T6 AEAD (3h); T8 simulator (2h) |
| 5 | 5 | T8 finish (3h); T7 ESP32 (2h) |
| 6 | 5 | T7 ESP32 (4h); T22b logging (1h) |
| 7 | 5 | T7 finish (2h); tests (2h); T22b (1h) |
| 8 | 4 | T24 calibration (3h); paper (1h) |
| 9 | 3 | T24 calibration (2h); paper (1h) |
| 10 | 2 | Paper sections |
| 11-13 | 1 each | Viva prep |

Peak weeks: 1 and 2-7 steady. Use the extra session time for debugging.

## 5. Week-1 go/no-go test (your most important task)
1. Build the crypto library and run a KEM and signature round trip on your laptop.
2. On the ESP32, run the chosen post-quantum handshake (Route A: DTLS 1.3 with post-quantum groups) or, if that fails, primitives only (Route B).
3. Record: key-generation time, handshake latency, peak heap use, handshake message sizes.
4. Report to the team by end of Week 1: which route works, and what the timings are. S3 and S4 use this to decide whether compute-failure classification stays.

## 6. Key rules
- Use a real library. Never write your own ML-KEM, ML-DSA or combiner.
- Never invent a new handshake or hybrid key combiner.
- Fix key roles in the interface spec (T2) with S2: which keys are long-term (gateway identity, policy authority) and which are per session.
- Nonces must never repeat under one key. Document your nonce scheme.
- Never log keys, shared secrets or plaintext payloads.
- Do not claim forward secrecy or end-to-end confidentiality.

## 7. Interfaces
- **Gives S2:** KEM, signature and AEAD modules with a documented API (Week 3-4).
- **Gives S3:** signature verification results and failure reasons.
- **Gives S4:** device logs in the agreed schema; calibration data (CPU/memory/timing) to calibrate emulated device classes.

## 8. Definition of done
- ESP32 completes a handshake and encrypted exchange with the gateway on the chosen route.
- Timings and memory recorded for every parameter set used.
- All crypto calls covered by known-answer or round-trip tests; tampered signatures are rejected.
- No secrets in logs.
- Paper sections drafted, and you can explain every key and signature check in the viva.

## 9. Risks and fallbacks
- Library build fails: try the other library or an OpenSSL provider (Week 1).
- ESP32 handshake not working by Week 5: switch to Route B, measure primitives on the ESP32 and run the rest with the simulator.
- Memory too tight: reduce parameter set or cut the ESP32 scenarios to a smaller set (S4 agrees the reduced matrix).

## 10. Viva topics to master
Where ML-KEM and ML-DSA are used; long-term versus session keys; how the session key protects payloads; nonce handling; why the gateway is trusted; what your ESP32 results do and do not show; why you claim no forward secrecy.

## 11. Approval
Any change to algorithm, parameter set or library: propose it, then S3 reviews, then the mentor approves.

---

# Add-on: What to do and how to do it

## A. Reference sizes (FIPS 203/204 values, useful for MTU reasoning)
| Item | ML-KEM-512 | ML-KEM-768 | ML-DSA-44 | ML-DSA-65 |
|------|-----------|-----------|-----------|-----------|
| Public key (bytes) | 800 | 1184 | 1312 | 1952 |
| Ciphertext / signature (bytes) | 768 | 1088 | 2420 | 3309 |

Hand these to S4: with a 1280-byte MTU, an ML-DSA signature or ML-KEM-768 public key already forces fragmentation. That is why fragmentation and loss matter in your experiments.

## B. Step by step
1. **Laptop first.** Install liboqs and its Python bindings (or OpenSSL 3.5 with its ML-KEM/ML-DSA support). Write a 30-line script: generate keys, encapsulate, decapsulate, check both sides agree; sign, verify, tamper one byte, confirm verification fails.
2. **Wrap it.** Put the primitives behind three small functions: `kem_keygen/encaps/decaps`, `sig_sign/verify`, `aead_encrypt/decrypt`. S2 and S3 only ever call these. Keep the API stable after Week 3.
3. **Session key derivation.** Derive the AEAD key from the KEM shared secret with a standard KDF (HKDF) and bind the device ID and a handshake nonce as context. Use a library HKDF. Do not invent a combiner.
4. **AEAD.** Use AES-GCM or ChaCha20-Poly1305 from a library. Use a per-session key and a counter-based nonce that never repeats; reject repeated counters.
5. **Tests.** Known-answer tests from library vectors, round trips, tamper tests (flip a ciphertext bit, expect failure), wrong-key tests.
6. **ESP32 (Week-1 test).**
   - Use ESP-IDF. Time operations with `esp_timer_get_time()`. Record free heap with `esp_get_free_heap_size()` and the low-water mark with `esp_get_minimum_free_heap_size()`.
   - Try Route A first (DTLS 1.3 with post-quantum groups). Confirm the exact library and version supports it on your board before committing.
   - If the build takes more than about a day of effort with no progress, switch to Route B: run only KEM and signature operations on the ESP32 and log timings and memory.
7. **Device simulator.** Write one program that takes a profile (Classical, Hybrid, PQC), a CPU limit and a memory limit. On Linux use `cgroups` or `systemd-run` (or Docker `--cpus` and `--memory`) to emulate classes. Calibrate the limits so simulator timings match your ESP32 measurements.
8. **Logging.** Emit one JSON line per event using S4's schema: `ts, device_id, flow_id, event, mode, cause, size_bytes, duration_ms`.

## C. Pitfalls
- Wrong key roles: write down who holds which key before coding.
- Nonce reuse under one key: this breaks AEAD security.
- Logging secrets: never print keys, shared secrets or plaintexts.
- Assuming the ESP32 works because the laptop did.

## D. Handoffs
- Week 3-4: crypto API to S2 and S3.
- Week 6-7: device logs and simulator to S4.
- Week 8-9: calibration data to S4.
