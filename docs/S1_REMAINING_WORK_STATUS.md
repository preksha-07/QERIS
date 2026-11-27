# QERIS S1 — Remaining Work Completion & Architectural Status

**Document Version:** 1.0.0
**Date:** 2026-11-26
**Status:** Canonical S1 Handover
**Scope:** Cryptography, Device Simulation, and Subsystem Handover (`qeris/s1/`)

---

## 1. Executive Summary

All core cryptographic, simulation, structured logging, and test verification tasks assigned to QERIS Step 1 (S1) are complete. S1 provides a self-contained, reproducible, and robust foundation covering:
- Classical session cryptography (X25519).
- Post-quantum session cryptography (ML-KEM-512).
- Hybrid post-quantum/classical session cryptography (X25519 + ML-KEM-768).
- Authenticated telemetry encryption with monotonic replay protection (AES-256-GCM).
- Canonical policy validation and offline authority signing (ML-DSA-65).
- Challenge-based device proof of possession (Ed25519).
- Local in-process device simulation with structured JSON event telemetry adhering to S4 logging contracts.
- Fixed-vector Known Answer Tests (KATs) and comprehensive regression coverage.

Physical ESP32 hardware implementation and physical bench measurements remain unperformed, documented as pending physical hardware access.

---

## 2. Test Baseline & Current Verification State

### 2.1 Automated Test Execution Summary
The complete S1 test suite executes cleanly under Python 3.13.14 with zero failures:
- **Baseline Suite:** 118 passed, 12 subtests passed in ~0.8s.
- **Enhanced Suite (with S1 Structured Logging Tests):** 125 passed, 15 subtests passed.
- **Flakiness & Isolation:** Zero flaky tests; all cryptographic operations are deterministically verified or seeded appropriately.

### 2.2 Test Suite Breakdown by Module
| Test Module | Coverage Scope | Status |
|---|---|---|
| `test_crypto_smoke.py` | Basic ML-KEM-512 and ML-DSA-65 sanity checks | Passed |
| `test_device_auth.py` | Ed25519 key generation, challenge signing, replay rejection, context tampering | Passed |
| `test_device_simulator.py` | End-to-end round trip for PQC, Classical, Hybrid; synthetic timeouts; structured logging | Passed |
| `test_offline_signer.py` | ML-DSA-65 offline authority CLI, atomic writes, overwrite prevention | Passed |
| `test_secure_message.py` | AES-256-GCM encryption, 96-bit monotonic counter, context-bound AAD, replay checks | Passed |
| `test_session_crypto.py` | ML-KEM-512 encap/decap, HKDF-SHA256 session key derivation, `handshake_id` binding | Passed |
| `test_signed_policy.py` | Canonical 5-field schema validation, anti-rollback ordering, ML-DSA-65 verification | Passed |
| `test_kats.py` | Fixed-vector Known Answer Tests for HKDF, Ed25519, AES-GCM, and PQC length/API tests | Passed |

---

## 3. Structured Device Event Logging (S1/S4 Contract)

### 3.1 Field Schema Conformance
S1 implements a dedicated structured event logging hook in `device_simulator.py`. Every simulated device operation emits an immutable, strictly validated dictionary conforming to the 8 agreed S4 fields:

| Field Name | Type | Description | Allowed / Observed Values |
|---|---|---|---|
| `ts` | `int` | Millisecond Unix timestamp | e.g., `1764173849123` |
| `device_id` | `str` | Device identifier | e.g., `"DEV-TEST-001"` |
| `flow_id` | `str` | Telemetry flow identifier | e.g., `"FLOW-TEMP-01"` |
| `event` | `str` | Lifecycle event identifier | `"connection_start"`, `"handshake_complete"`, `"data_sent"`, `"failure"` |
| `mode` | `str` | Cryptographic profile mode | `"PQC"`, `"CLASSICAL"`, `"HYBRID"` |
| `cause` | `str` | Error cause or `"none"` | `"none"`, `"timeout"`, `"invalid_payload"`, `"invalid_profile"` |
| `size_bytes` | `int` | Artifact or message byte size | e.g., `800` (PQC pk), `2336` (Hybrid wire), `121` (envelope) |
| `duration_ms` | `float` | Step execution duration in ms | e.g., `1.234` |

### 3.2 Confidentiality Guarantee
In accordance with S1 Security Rule 5:
- **No Secret Key Material:** Private keys, seed buffers, shared secrets, and derived session keys are strictly excluded from event dictionaries and JSON serializations.
- **No Plaintext Leakage:** Application telemetry plaintext is never embedded in logs; only the encrypted envelope size (`size_bytes`) is reported.
- **Serialization:** Canonical compact JSON serialization (`serialize_device_event`) is provided.

---

## 4. Simulator CPU & Memory Calibration Status

### 4.1 Synthetic Simulation Parameters
The device simulator provides synthetic latency and timeout knobs via `SimulatorConfig`:
- `compute_delay_seconds`: Injects synthetic pauses before major cryptographic phases.
- `timeout_seconds`: Triggers `SimulatorTimeoutError` when operations exceed expected thresholds.

### 4.2 Explicit Lack of Hardware Calibration
- **Uncalibrated Status:** These synthetic delay values are **not** calibrated from real ESP32 hardware benchmarks. They exist solely to test asynchronous timeout detection, S1 failure callbacks, and S3 recovery triggers.
- **No Synthetic Hardware Claims:** S1 explicitly prohibits presenting simulated delay values, synthetic memory footprints, or estimated CPU cycle counts as measured ESP32 data.
- **Extension Points:** The simulator is structured such that real execution profiles (measured via hardware testbeds) can be injected into `SimulatorConfig` once physical ESP32 measurements become available.

---

## 5. Subsystem Handover & Integration Boundaries

### 5.1 S2 Gateway Handover
1. **Profile Negotiation:** S2 gateway must recognize and support all three S1 profiles: `DeviceProfile.PQC`, `DeviceProfile.CLASSICAL`, and `DeviceProfile.HYBRID`.
2. **Handshake Transcript Binding:** S2 must compute and compare `handshake_id` against the device's token to ensure strict channel binding before accepting telemetry.
3. **Anti-Rollback State Store:** S2 must persist the highest accepted `policy_version` per flow across gateway restarts. S1 provides the verification logic (`verify_policy_envelope`), but persistence is S2's responsibility.
4. **Device Registry & Ed25519 Auth:** S2 must query `devices.json` to verify device enrollment and validate Ed25519 challenge-response signatures using `qeris.device_auth`.

### 5.2 S3 Security & Recovery Handover
1. **Exception Taxonomy Mapping:** S3 must map S1 cryptographic exceptions to S3 recovery causes:
   - `SimulatorTimeoutError` -> `CauseClass.TIMEOUT`
   - `ReplayError` -> `CauseClass.REPLAY_DETECTED`
   - `AuthenticationError` / `InvalidSignatureError` -> `CauseClass.AUTH_FAILURE`
   - `CryptoInputError` / `InvalidPayloadError` -> `CauseClass.MALFORMED_INPUT`
2. **Floor Enforcement:** S3 recovery state machines must maintain the cryptographic security floor and never downgrade from PQC or Hybrid to Classical without authorized policy trigger.

### 5.3 S4 Evaluation & Analytics Handover
1. **Event Telemetry Ingestion:** S4 can ingest S1 events directly via `SimulatorConfig(event_hook=...)` or by querying `SimulationResult.events`.
2. **MTU & Fragmentation Analysis:** S4 should consume the cryptographic object size definitions documented in `S1_MTU_HANDOVER.md` to compute theoretical fragmentation overhead.

---

## 6. Security & Repository Hygiene Audit

### 6.1 Private Key Audit Findings
- **S1 Directory Audit (`qeris/s1/`):**
  - Confirmed: **Zero private keys, authority keys, or cached secrets exist in `qeris/s1/`**.
  - All test keys are generated ephemerally in-memory using CSPRNGs or isolated temporary directories.
- **Repository Authority Key Audit (`qeris/s2/authority_keys/`):**
  - Finding: An ML-DSA-65 secret key (`qeris_gateway.key`, 4032 bytes) is committed to disk in `qeris/s2/authority_keys/`.
  - Severity: Operational / Key Management Risk.
  - Action & Warning Issued: While outside S1's modification boundary, S1 issues a formal security advisory to the S2 Authority Owner:
    > **WARNING:** The file `qeris/s2/authority_keys/qeris_gateway.key` contains an active private key. If this repository checkout has been distributed or archived in unencrypted form, this key must be marked untrusted and rotated before production deployment.

### 6.2 Documentation Link Audit
- All 10 legacy absolute local file links (`file:///C:/Users/sahan/...`) in `qeris/s1/docs/S1_FINAL_HANDOVER.md` have been identified, removed, and replaced with portable relative links.
- Verified: Zero absolute file URLs remain in `qeris/s1/docs/`.

---

## 7. Definition of Done (DoD) Verification Checklist

| Criterion | Implementation & Evidence | Status |
|---|---|---|
| **PQC Key Exchange** | ML-KEM-512 encap/decap in `session_crypto.py`; verified by unit tests & KATs | **DONE** |
| **Classical Key Exchange** | X25519 ECDH in `qeris_classical/session_crypto.py`; verified by unit tests & KATs | **DONE** |
| **Hybrid Key Exchange** | X25519MLKEM768 in `hybrid_session_crypto.py`; RFC 10024 share order + RFC 9958 combiner | **DONE** |
| **Key Derivation** | HKDF-SHA256 with 4-tuple length-prefixed context binding in `session_crypto.py` | **DONE** |
| **Message Protection** | AES-256-GCM with 96-bit monotonic counter and AAD in `secure_message.py` | **DONE** |
| **Device Authentication** | Challenge-response Ed25519 proof of possession in `device_auth.py` | **DONE (Classical)** |
| **Policy Authority** | Canonical 5-field schema + ML-DSA-65 offline signer in `policy/offline_signer.py` | **DONE** |
| **Event Logging** | Structured JSON events (`ts, device_id, flow_id, event, mode, cause, size_bytes, duration_ms`) | **DONE** |
| **Simulator Profiles** | Local in-process simulator supporting PQC, Classical, Hybrid in `device_simulator.py` | **DONE** |
| **Hardware Caveats** | Clear documentation that ESP32 calibration and physical wire MTUs are unperformed | **DONE** |
| **Hygiene Check** | Zero absolute links in S1 docs; zero private keys in `qeris/s1/` | **DONE** |
