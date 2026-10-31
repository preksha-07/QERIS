# QERIS — Complete Backend Integration Audit
**Document:** `docs/INTEGRATION_AUDIT.md`  
**Date:** 2026-10-31  
**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway  
**Author:** Backend Integration Team  

---

## 1. Executive Summary

This audit evaluates the current integration baseline of the QERIS repository across all four subsystems:
- **S1:** Cryptography & Device Layer (ML-KEM-512, ML-DSA-65, HKDF-SHA256, AES-256-GCM, signed policy proof-of-concept).
- **S2:** Gateway, Policy & Cloud Integration Layer (FastAPI gateway, policy registry, capability registry, crypto adapter).
- **S3:** Security Logic & Recovery Layer (Downgrade rejection, failure taxonomy, recovery controller, floor state machine, replay protection, structured audit logging).
- **S4:** Evaluation & Benchmark Layer (Log schema, ground-truth harness, baseline engine, statistical analysis, table/figure generation).

### Key Findings
1. **Core Cryptography & Logic Work Well in Isolation:**
   - S1 unit tests (54/54 passed when executed in `qeris/s1`).
   - S3 unit and invariant tests (103/103 passed when executed in `qeris/s3`).
   - S4 evaluation and baseline tests (44/44 passed when executed in `qeris/s4`).
   - Total existing passing test suite: **201 tests**.
2. **Mandatory Schema Discrepancy (S1 vs S2):**
   - **S2 (Source of Truth):** 5-field flow-centric policy schema: `flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`.
   - **S1 (Outdated Provisional Prototype):** 6-field dictionary schema: `version`, `sig_alg`, `flow_to_tier`, `tier_to_suite`, `expiry`, `revocation_list`.
   - **Action Required:** Align S1 policy serialization, validation, signing, verification, and tests strictly to S2's canonical 5-field schema.
3. **Module Interconnection Gaps:**
   - S2 loads `policy.json` as raw static JSON without cryptographic signature verification (S1).
   - S2 decision flow in `gateway.py` does not invoke S3's `S3GatewayHook.process_gateway_decision()`.
   - S2 audit logs (`gateway_logs.jsonl`) are written in an ad-hoc format disconnected from S3's `AuditLogger` and S4's canonical `LogRecord` schema.
   - S1 modules reside in a nested `qeris/s1/qeris/` sub-package that shadows the root `qeris` package during top-level pytest collection.

---

## 2. Existing Implementation Analysis

### 2.1 Subsystem S1 — Cryptography and Device Layer
- **Source Directory:** `qeris/s1/qeris/`
- **Key Modules:**
  - `session_crypto.py`: ML-KEM-512 (`oqs.KeyEncapsulation`) keypair generation, encapsulation, decapsulation; HKDF-SHA256 context-bound session key derivation (`device_id`, `flow_id`, `sensitivity_tier`, `policy_version`).
  - `secure_message.py`: AES-256-GCM authenticated encryption/decryption (`MessageEncryptor`, `MessageDecryptor`) with 96-bit monotonic counter, 12-byte nonce, explicit binary header (`QMSG\x01<nonce>`), and AAD context binding.
  - `device_simulator.py`: In-process simulator (`SimulatedDevice`, `SimulatedReceiver`) demonstrating KEM handshake and telemetry encryption.
  - `policy/serialization.py`: Deterministic JSON serialization (`serialize_policy_to_bytes`, `deserialize_policy_from_bytes`) with strict duplicate-key rejection and non-standard constant rejection.
  - `policy/signed_policy.py`: ML-DSA-65 (`oqs.Signature`) policy signing and verification with status enum (`PolicyVerificationStatus`), in-memory monotonic anti-rollback check.
- **Current Strengths:** Robust liboqs-python wrapper, zero leakage of private keys/shared secrets, strict parameter checking.
- **Defects & Gaps:** Validates the provisional 6-field schema instead of S2's 5-field canonical schema; lacks authority public-key registry; lacks signature envelope decoupling.

---

### 2.2 Subsystem S2 — Gateway, Policy & Cloud Layer
- **Source Directory:** `qeris/s2/`
- **Key Modules:**
  - `gateway.py`: FastAPI application serving `POST /check-flow` and `POST /crypto-demo`. Evaluates flow feasibility, policy floor, and device capability.
  - `crypto_adapter.py`: Adapter connecting S2 to S1 `session_crypto` and `secure_message` for local round-trip demonstration.
  - `policy.json`: The source of truth for flow policies:
    ```json
    {
      "temperature_01": {
        "sensitivity": "LOW",
        "minimum_mode": "CLASSICAL",
        "policy_version": 1,
        "authority_id": "QERIS-GATEWAY"
      },
      "emergency_stop": {
        "sensitivity": "CRITICAL",
        "minimum_mode": "HYBRID",
        "policy_version": 1,
        "authority_id": "QERIS-GATEWAY"
      }
    }
    ```
  - `devices.json`: Capability registry:
    - `device_001`: `["CLASSICAL", "HYBRID"]`
    - `device_002`: `["CLASSICAL", "HYBRID", "PQC"]`
    - `device_003`: `["CLASSICAL"]`
- **Current Strengths:** Working policy resolution, floor feasibility checks, CORS support, working integration with UI transmission simulator.
- **Defects & Gaps:** No S1 signature verification on load; no persistent anti-rollback validation; does not call S3 security/recovery hook; ad-hoc JSONL audit logging.

---

### 2.3 Subsystem S3 — Security Logic & Recovery Layer
- **Source Directory:** `qeris/s3/`
- **Key Modules:**
  - `downgrade_rejection.py`: `DowngradeRejector` enforcing security floor invariants across `CLASSICAL` (1), `HYBRID` (2), `PQ`/`PQC` (3).
  - `floor_state_machine.py`: Formal FSM tracking policy and session lifecycle: `INITIAL` -> `REGISTERED` -> `POLICY_VALID` -> `NEGOTIATING` -> `ACTIVE` (or `DEGRADED`, `QUARANTINED`).
  - `failure_taxonomy.py`: `FailureTaxonomy` mapping observed failure signals to root causes: `security_failure`, `mtu_fragment`, `loss_timeout`, `none`. Includes `ObservedSignals.from_s1_status()`.
  - `recovery_controller.py`: `RecoveryController` implementing bounded retries, exponential backoff, MTU refragmentation, and immediate session termination on security violations.
  - `replay_protection.py`: `ReplayProtection` managing persistent anti-rollback version storage with atomic updates.
  - `audit_logger.py`: Structured JSON logger enforcing no secrets, rate limiting, and dedicated `SECURITY` severity.
  - `s3_gateway_hook.py`: Complete integration hook designed to sit between S2 `check_flow` and the gateway response.
- **Current Strengths:** Highly modular, rigorous invariant test coverage, clean state machines and taxonomy.
- **Defects & Gaps:** Hook is not actively called by S2 `gateway.py`; authority registry is hardcoded to a static set.

---

### 2.4 Subsystem S4 — Data Science & Evaluation Layer
- **Source Directory:** `qeris/s4/`
- **Key Modules:**
  - `log_schema.py`: Canonical schema (`LogRecord`) specifying 15 standard fields for benchmark logging.
  - `log_parser.py`: Robust JSONL parser with validation and column extraction.
  - `ground_truth_harness.py`: Ground-truth benchmark scenario catalog with cause attribution.
  - `fault_injection.py`: Controlled synthetic channel degradation models (loss, latency, MTU, security attacks).
  - `baseline_engine.py`: Baseline migration comparison implementations (7 baselines).
  - `experiment_runner.py` / `experiment_matrix.py`: Pilot and full benchmark execution engines.
  - `analysis.py`: Wilson score confidence intervals, confusion matrix generation, table/figure generation.
- **Current Strengths:** Complete statistical framework, rigorous invariant checking, zero external data dependencies.
- **Defects & Gaps:** S4 currently reads its own benchmark runs rather than ingesting real gateway traces produced during runtime.

---

## 3. Schema Mismatch Detail (S1 vs S2)

| Dimension | S2 Existing Schema (Source of Truth) | S1 Outdated Provisional Schema | Resolution |
| :--- | :--- | :--- | :--- |
| **Record Scope** | Per-flow policy item | Monolithic multi-flow policy | S1 must validate canonical per-flow records |
| **Field 1** | `flow_id` (str) | *None* (stored inside `flow_to_tier` map) | Standardize `flow_id` as mandatory |
| **Field 2** | `sensitivity` ("LOW", "CRITICAL", etc.) | *None* (tier string in map) | Standardize `sensitivity` as mandatory |
| **Field 3** | `minimum_mode` ("CLASSICAL", "HYBRID", "PQC") | `tier_to_suite` (cryptographic suite map) | Standardize `minimum_mode` as mandatory |
| **Field 4** | `policy_version` (int >= 1) | `version` (int >= 1) | Standardize `policy_version` as mandatory |
| **Field 5** | `authority_id` (str) | *None* | Standardize `authority_id` as mandatory |
| **Envelope** | Inherent in JSON key/structure | Implicit in signed payload (`sig_alg`) | Explicit envelope: `{ policy: {5 fields}, sig_alg: "ML-DSA-65", signature: "<hex>" }` |
| **Extra Fields** | *None* | `sig_alg`, `flow_to_tier`, `tier_to_suite`, `expiry`, `revocation_list` | Remove extra fields from mandatory canonical policy |

---

## 4. Baseline Test Results

All existing unit test suites were executed on 2026-10-31 using Python 3.13.14 with `liboqs-python` 0.16.0.1 and `pytest` 9.2.0:

| Subsystem | Test Suite | Tests Run | Passed | Failed | Errors |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **S1** | `qeris/s1/tests/test_crypto_smoke.py` | 6 | 6 | 0 | 0 |
| **S1** | `qeris/s1/tests/test_device_simulator.py` | 4 | 4 | 0 | 0 |
| **S1** | `qeris/s1/tests/test_secure_message.py` | 10 | 10 | 0 | 0 |
| **S1** | `qeris/s1/tests/test_session_crypto.py` | 8 | 8 | 0 | 0 |
| **S1** | `qeris/s1/tests/test_signed_policy.py` | 26 | 26 | 0 | 0 |
| **S1 Subtotal** | *All S1 tests* | **54** | **54** | **0** | **0** |
| **S3** | `qeris/s3/test_integration.py` | 38 | 38 | 0 | 0 |
| **S3** | `qeris/s3/test_invariants.py` | 65 | 65 | 0 | 0 |
| **S3 Subtotal** | *All S3 tests* | **103** | **103** | **0** | **0** |
| **S4** | `qeris/s4/test_s4.py` | 44 | 44 | 0 | 0 |
| **S4 Subtotal** | *All S4 tests* | **44** | **44** | **0** | **0** |
| **Total Baseline** | | **201** | **201** | **0** | **0** |

*Note:* When pytest is executed from the repository root, S1 tests currently trigger import collection errors due to `qeris/s1/qeris/` namespace overlap. This packaging issue will be resolved during integration.

---

## 5. Integration Road Map

1. **Phase 2 (Schema Alignment):**
   - Refactor S1 `serialization.py` and `signed_policy.py` to canonical 5-field schema.
   - Introduce `PolicyEnvelope` decoupling policy data from signature metadata.
   - Update S1 unit tests to test the 5-field schema.
   - Create `docs/POLICY_CONTRACT.md`.
2. **Phase 3 (S1-S2 Integration):**
   - Implement policy signer utility to generate signed policy envelopes.
   - Integrate signature verification into S2 policy loading with trusted authority key lookup.
   - Update `crypto_adapter.py` to enforce verified policy context.
   - Create `docs/S1_S2_INTEGRATION.md`.
3. **Phase 4 (S2-S3 Integration):**
   - Connect S2 `gateway.py` request pipeline to `S3GatewayHook`.
   - Incorporate `ReplayProtection` for persistent anti-rollback validation.
   - Standardize event fields (`trace_id`, `failure_cause`, `recovery_action`).
   - Create `docs/S2_S3_INTEGRATION.md`.
4. **Phase 5 (S4 Integration):**
   - Provide adapter bridge between S3 audit log events and S4 `LogRecord`.
   - Create `docs/S3_S4_INTEGRATION.md` and `docs/S4_INTEGRATION.md`.
5. **Phase 6 & 7 (Architecture & Final Validation):**
   - Create `docs/ARCHITECTURE.md` and `docs/BACKEND_SETUP.md`.
   - Add end-to-end multi-module integration tests verifying the full chain:
     `S1 Signed Policy -> S2 Gateway -> S3 Security & Recovery -> S1 Crypto -> S4 Event Log`.
