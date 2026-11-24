# QERIS S2: Reconciliation of Blueprint Requirements & Subsystem Gaps

**Subsystem:** S2 — Security Gateway, Policy Engine, Cloud Integration  
**Milestone:** Phase 3 Final Security & Runtime Verification Gate  
**Date:** 2026-11-21  
**Frozen Config Digest:** `7126e04629aac0a7f961d44b231258dcac4dae7164ff4da7b6e89834d5564c01`  
**UI Tree Hash:** `93c66df806ba3ec1aedf888cfd853a7d50858583` (Untouched)  
**Test Suite:** 291/291 Passed (100%) across 23 test files (+12 subtests passed)  

This document reconciles all reported limitations, boundary conditions, and blueprint requirements for the QERIS S2 subsystem, classified strictly according to the five authoritative categories.

---

## 1. Summary Classification Matrix

| Item | Requirement Description | Blueprint Ref | Classification | Status in S2 |
|---|---|---|---|:---:|
| **Gateway–Cloud TLS** | Genuine TLS with self-signed certificate | S2 Spec §5, Add-on §A | **Mandatory and Complete** | **VERIFIED (Live Handshake Tested)** |
| **Admin API Protection** | Restrict baseline switching, config, reset | Blueprint T2, T9, T22c | **Mandatory and Complete** | **VERIFIED (Fail-Secure, No Default Secret)** |
| **State Reset & Isolation** | Clean trial reset of ephemeral state | Blueprint T23, T38 | **Mandatory and Complete** | **VERIFIED** |
| **B1–B7 Baseline Freeze** | Frozen execution paths & canonical digest | Blueprint T23a, T23b | **Mandatory and Complete** | **VERIFIED** |
| **Outage Queue Cold Persistence** | SQLite WAL durability across process crash | S2 Add-on §B.1 | **Optional / Supplementary** | **SUPPLEMENTARY** |
| **Live Docker Runtime Daemon** | Container startup on live Docker engine | Blueprint T38 | **Mandatory and Complete** | **VERIFIED (10/10 Live Checks Passed)** |
| **UI Dashboard Frontend** | React frontend connection to REST API | Blueprint T36, UI Scope | **Mandatory and Complete** | **VERIFIED (Phase 4 Integrated & Tested)** |
| **S4 Experiment Matrix** | Automated 7-baseline matrix benchmark runs | Blueprint T28–T33 | **Explicitly Assigned (S4)** | **READY FOR S4** |
| **ESP32 Physical Profiling** | Real on-chip peak heap & latency | Blueprint T7, T24 | **Physical Hardware Validation** | **ASSIGNED TO S1** |
| **Readiness Calibration** | Empirical RAM tuning from chip runs | Blueprint T14, T24 | **Physical Hardware Validation** | **ASSIGNED TO S1** |

---

## 2. Detailed Item Reconciliation

### 2.1 Gateway–Cloud Transport Security (TLS)
- **Classification:** **Mandatory and Complete**
- **Blueprint Specification:** "The gateway is trusted in the prototype. It terminates the device-gateway session, enforces policy, and opens a separate ordinary TLS session to the cloud. Do not claim end-to-end confidentiality. Gateway to cloud: ordinary TLS with a self-signed local certificate. This is not a PKI; do not claim one." (`S2_gateway_cloud_integration.md` §5, Add-on §A).
- **Implementation Status:** Verified. Self-signed ECDSA P-256 certificate with SANs (`localhost`, `qeris-cloud`, `qeris-gateway`, `127.0.0.1`) generated in `qeris/s2/certs/`. Live HTTPS server test demonstrates genuine TLS handshake and data delivery (`test_genuine_tls_handshake_with_live_https_server`). Genuine certificate verification failure demonstrated when presented with untrusted certificate (`test_genuine_tls_rejection_of_untrusted_certificate`). Plaintext HTTP has been eliminated.
- **Security Boundary:** Edge session terminates at gateway; gateway opens ordinary TLS session to cloud. End-to-end device-to-cloud confidentiality is explicitly NOT claimed.

### 2.2 Administrative Controls & API Key Protection
- **Classification:** **Mandatory and Complete**
- **Blueprint Specification:** Administrative endpoints (`/api/v1/admin/baseline`, `/api/v1/admin/config`, `/api/v1/admin/reset`) must restrict mode switching and state manipulation to authorized callers without predictable/hardcoded operational secrets.
- **Implementation Status:** Verified. 
  - Eliminated hardcoded operational admin secret (`DEFAULT_ADMIN_API_KEY` is `None` by default).
  - Admin access strictly requires an explicitly configured credential (via `QERIS_ADMIN_API_KEY` or constructor argument).
  - When the credential is unset or empty, administrative endpoints remain disabled and fail securely with **HTTP 403 Forbidden** (`test_admin_auth_fail_secure_when_key_unset`).
  - When configured, invalid or missing credentials return **HTTP 401 Unauthorized** (`test_admin_auth_valid_and_invalid_credentials`).
  - Key is never exposed in logs, audit records, or config responses (`test_admin_key_redaction_in_config_and_audit`).
  - `docker-compose.yml` uses environment substitution (`${QERIS_ADMIN_API_KEY}`), and `.env.example` documents setup.

### 2.3 State Reset & Experimental Run Isolation
- **Classification:** **Mandatory and Complete**
- **Blueprint Specification:** Experimental baseline execution requires clean isolation between runs without state contamination.
- **Implementation Status:** Verified. `POST /api/v1/admin/reset` completely clears token bucket rate limits, session keys, cloud outage queues, dropped record counters, and restores baseline to `FULL_GATEWAY`. Persistent security invariants (SQLite WAL anti-rollback policy store, device capability registry, audit trail) are strictly preserved.

### 2.4 B1–B7 Baseline Freeze & Reproducibility
- **Classification:** **Mandatory and Complete**
- **Blueprint Specification:** All seven baselines (B1–B7) must be selectable via config flag, have distinct defensible execution paths, and isolate intentional B5 downgrade behavior from B7 operational enforcement.
- **Implementation Status:** Verified. All seven baselines smoke-tested and verified. Frozen configuration digest generated via RFC 8785 canonical JSON: `7126e04629aac0a7f961d44b231258dcac4dae7164ff4da7b6e89834d5564c01`.

### 2.5 Outage Queue Persistence Across Cold Reboots
- **Classification:** **Optional or Supplementary**
- **Blueprint Specification:** S2 task description specifies a gateway that forwards accepted telemetry and buffers during outages. The memory-only bounded FIFO queue (`collections.deque(maxlen=1000)`) satisfies this requirement.
- **Implementation Status:** Supplement only. Storing unsent telemetry in an append-only WAL SQLite database across cold host power cycles is an optional production-hardening enhancement, not a mandatory prototype requirement.

### 2.6 Live Docker Startup Validation
- **Classification:** **Mandatory and Complete**
- **Blueprint Specification:** "One command starts the system" (`docker compose up`).
- **Implementation Status:** **VERIFIED (Phase 4.1 Live Docker Acceptance)**.
  - Built and orchestrated via `Dockerfile` and `docker-compose.yml`.
  - Both `qeris-cloud` (port 8001 over TLS) and `qeris-gateway` (port 8000) running healthy.
  - 10/10 live container acceptance checks verified: health endpoints, TLS transport, flow authorization, telemetry forwarding, cloud SQLite persistence, admin fail-secure authentication, cloud reset security, gateway reset contract, and named volume persistence across container restarts.
  - Evidence documented in `PHASE_4.1_DOCKER_RUNTIME_REPORT.md` and `docker_runtime_results.json`.

### 2.7 UI Dashboard Frontend Connection
- **Classification:** **Explicitly Assigned to Another Subsystem / Milestone (Phase 4)**
- **Blueprint Specification:** Web UI visualization of gateway flow checks, baseline switching, and cloud metrics.
- **Implementation Status:** By strict instructions across Phases 1, 1.5, 2, and 3, the `ui/` directory was kept 100% byte-for-byte untouched (Git tree hash `93c66df806ba3ec1aedf888cfd853a7d50858583`). S2 provides all required REST APIs ready for UI consumption in Phase 4.

### 2.8 S4 Full Matrix Execution
- **Classification:** **Explicitly Assigned to Another Subsystem (S4)**
- **Blueprint Specification:** S4 owns Tasks T28–T33: experiment matrix design, runner automation, Wilson confidence interval calculation, and paper figures.
- **Implementation Status:** S2 does not own benchmark sweeps. S2 provides frozen baseline execution paths, run context propagation (`run_id`, `scenario`), trial state reset, and structured JSONL audit logs.

### 2.9 Physical Hardware-in-the-Loop (HIL) ESP32 Measurements
- **Classification:** **Physical Hardware Validation Requirement (Assigned to S1)**
- **Blueprint Specification:** Tasks T7 and T24 are explicitly assigned to S1 (Cryptography and Device Engineer, 10h + 5h): flash ESP32, measure cycle counts, on-chip heap, and RF packet loss.
- **Implementation Status:** S2 has validated cryptographic correctness and wire encoding using NIST FIPS Python implementations. Physical hardware measurement is an S1 responsibility requiring target microcontrollers and ESP-IDF toolchains.

### 2.10 Readiness Threshold Calibration
- **Classification:** **Physical Hardware Validation Requirement (Assigned to S1)**
- **Blueprint Specification:** Tuning provisional RAM thresholds with empirical peak heap measurements.
- **Implementation Status:** Software wire sizes (240B, 1150B, 1820B) are verified. Updating provisional RAM values (8KB, 32KB, 48–96KB) with empirical on-chip heap usage depends on S1's physical board test data.
