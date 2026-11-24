# QERIS S2: Security Gateway and Cloud Integration Core

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems  
**Primary Research Contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes.

---

## 1. Overview

The `qeris/s2/` module implements the complete gateway core, persistent anti-rollback policy engine, capability and readiness classification system, gateway-to-cloud forwarding pipeline with bounded outage resilience, structured audit logging, per-device rate limiting, and state-machine integration hooks for QERIS.

The gateway serves as a policy-enforcing, cryptographic boundary sitting between constrained IoT edge devices (e.g., ESP32) and backend cloud services.

---

## 2. Architecture & Subsystems

```
                                  +---------------------------------------+
                                  | Policy Signing Authority (Offline)    |
                                  | - FIPS 204 ML-DSA-65 Digital Signature|
                                  +---------------------------------------+
                                                      |
                                                      | TB3: Signed Policy Envelopes
                                                      v
+---------------+  TB1: Untrusted Transport +---------------------------------------+  TB2: TLS / HTTP  +-----------------------+
|  IoT Device   | ========================> | QERIS Security Gateway                | ================> | Backend Cloud Service |
| (ESP32/Edge)  | (KEM-derived AEAD session)|  - RFC 8785 Canonical UTF-8 JSON      | (Forwarding Pipe) | - FastAPI / SQLite DB |
+---------------+                           |  - PolicyStore (Anti-Rollback DB)     |                   | - Ingestion & Query   |
                                            |  - Capability Registry & Readiness    |                   | - Sensitivity Segreg. |
                                            |  - DEC-4 Policy Epoch Session Manager |                   +-----------------------+
                                            |  - Token-Bucket Rate Limiter          |
                                            |  - S3 FSM Cause-Classified Recovery   |
                                            |  - Bounded Outage Buffer (1000 items) |
                                            |  - Structured Audit Logger (JSONL)    |
                                            +---------------------------------------+
```

### Core Components in `qeris/s2/`:
1. **`canonical_json.py`:** Deterministic RFC 8785-aligned JSON serializer and SHA-256 policy digest calculator with domain prefix `QERIS-POLICY-v1:`.
2. **`crypto_engine.py`:** NIST FIPS 204 ML-DSA-65 signature engine, FIPS 203 ML-KEM session derivation, and AES-256-GCM AEAD message envelope with context-bound AAD and counter replay protection.
3. **`policy_schema.py`:** Pydantic models for `FlowPolicyModel`, `PolicyDocumentModel`, and `SignedPolicyEnvelopeModel` enforcing profile-set security floors and device scope.
4. **`policy_signer.py` & `policy_verifier.py`:** Offline policy signing and strict cryptographic verification rejecting tampered payloads, unknown authorities, and invalid algorithms.
5. **`policy_store.py`:** Persistent SQLite anti-rollback store (`policy_store.db`) enforcing monotonic versioning across restarts and atomic disk-commit before memory activation.
6. **`capability_registry.py` & `readiness.py`:** SQLite device registry (`device_registry.db`) and pure deterministic readiness evaluation (`READY`, `PARTIALLY_READY`, `NOT_READY`).
7. **`session_manager.py`:** Gateway session manager implementing DEC-4 atomic policy-epoch invalidation for in-flight sessions.
8. **`rate_limiter.py`:** Thread-safe per-device token-bucket rate limiter defending against DoS/floods.
9. **`s3_adapter.py`:** Integration adapter bridging gateway decisions to the S3 state-machine hook (`qeris/s3/s3_gateway_hook.py`).
10. **`cloud_service.py` & `cloud_client.py`:** Cloud telemetry service (`cloud_telemetry.db`) and gateway forwarding client with a 1000-item bounded FIFO outage queue.
11. **`audit_logger.py`:** Machine-readable structured JSONL audit logger (`gateway_audit.jsonl`) aligned with S4 schemas, redacting all cryptographic secrets.
12. **`gateway_service.py` & `gateway.py`:** Unified FastAPI application exposing all standard endpoints (`/check-flow`, `/api/v1/handshake/*`, `/api/v1/telemetry`, `/api/v1/admin/*`).
13. **`data_replay.py`:** Real experimental dataset replayer processing data from `data/raw/pilot_smoke/`.
14. **`device_simulator.py`:** End-to-end security test harness demonstrating valid flows, downgrade blocking, fake label rejection, and flood defense.
15. **`generate_evidence.py`:** Generates structured JSON evidence files in `qeris/s2/evidence/`.

---

## 3. Core Invariants Enforced

| Invariant | Description | Enforcement Mechanism |
|---|---|---|
| **INV-1: Anti-Rollback** | Policy version must strictly increase monotonically ($v_{new} > v_{current}$). | `PolicyStore.install_policy()` SQLite transaction; rejects lower or equal versions with HTTP 409 (except exact duplicate digest). |
| **INV-2: Security Floor** | Traffic below policy-approved profile set is blocked ($M_{req} \notin P_{approved} \implies \text{REJECT}$). | Gateway checks policy profile intersection; blocks downgrade attempts even under network faults. |
| **INV-3: Authoritative Policy** | Device-supplied sensitivity claims are untrusted. | Sensitivity is derived strictly from the signed policy document, ignoring client payload claims. |
| **INV-4: Post-Commit Activation** | Policy must never be activated in RAM before disk persistence. | SQLite disk write and commit precedes in-memory pointer update. |
| **INV-5: Readiness Non-Downgrade** | `NOT_READY` state halts negotiation without downgrade. | Returns `FLOOR_UNREACHABLE` without falling back to insecure modes. |
| **INV-6: DEC-4 Session Invalidation** | Policy updates immediately invalidate active sessions using stale profiles. | `GatewaySessionManager.validate_and_rebind()` marks sessions `STALE` if the negotiated profile is removed in the new policy epoch. |
| **INV-7: Bounded Outage Buffer** | Cloud disconnection buffers up to 1000 records; oldest discarded on overflow. | Memory-bounded FIFO queue in `CloudForwardingClient`. |
| **INV-8: Strict Secret Redaction** | Audit logs must never contain private keys, symmetric keys, or plaintext secrets. | `GatewayAuditLogger` sanitizes and hashes sensitive context. |

---

## 4. Verification and Test Results

The full test suite across all modules passes with zero errors:

```powershell
.\.venv\Scripts\pytest.exe -v
```

| Module | Test File | Test Count | Result |
|---|---|---|---|
| **S2 Core** | `test_canonical_json.py` | 5 | **PASSED** |
| **S2 Core** | `test_policy_signing.py` | 4 | **PASSED** |
| **S2 Core** | `test_policy_store_anti_rollback.py` | 6 | **PASSED** |
| **S2 Core** | `test_security_floor_enforcement.py` | 5 | **PASSED** |
| **S2 Core** | `test_capability_readiness.py` | 6 | **PASSED** |
| **S2 Core** | `test_session_epoch_dec4.py` | 5 | **PASSED** |
| **S2 Core** | `test_cloud_pipeline_and_outage.py` | 4 | **PASSED** |
| **S2 Core** | `test_audit_logging.py` | 3 | **PASSED** |
| **S2 Core** | `test_rate_limiter.py` | 3 | **PASSED** |
| **S2 Core** | `test_s3_integration.py` | 3 | **PASSED** |
| **S2 Core** | `test_end_to_end.py` | 3 | **PASSED** |
| **S1 Crypto** | `test_crypto_smoke.py` | 6 | **PASSED** |
| **S1 Crypto** | `test_device_simulator.py` | 4 | **PASSED** |
| **S1 Crypto** | `test_secure_message.py` | 10 | **PASSED** |
| **S1 Crypto** | `test_session_crypto.py` | 7 | **PASSED** |
| **S1 Crypto** | `test_signed_policy.py` | 27 | **PASSED** |
| **S3 FSM** | `test_s3_comprehensive.py` | 91 | **PASSED** |
| **S3 FSM** | `test_s3_gateway_hook.py` | 12 | **PASSED** |
| **S4 Analysis**| `test_s4.py` | 44 | **PASSED** |
| **Total** | **20 Test Files** | **248 Tests** | **248 PASSED (100%)** |

---

## 5. UI Protection Verification

The UI directory (`ui/`) is strictly protected and remains byte-for-byte untouched:
- **UI Git Tree Hash:** `93c66df806ba3ec1aedf888cfd853a7d50858583`
- **Git Status:** Clean (`git status -- ui/` returns 0 modified files).
- Backend APIs (`/check-flow`, `/api/v1/telemetry`, `/api/v1/cloud/*`) implement clean JSON contracts matching the frontend expectations without modifying frontend files.

---

## 6. Execution Evidence

Structured evidence files generated in `qeris/s2/evidence/`:
- `policy_anti_rollback_evidence.json`
- `security_floor_enforcement_evidence.json`
- `cloud_pipeline_and_outage_evidence.json`
- `dataset_replay_evidence.json`
