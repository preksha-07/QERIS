# QERIS S2: Baseline Freeze and Experimental Readiness Specification

**Document Version:** 2.0.0-frozen  
**Frozen Configuration Digest:** `328a49ac4c1e66dca7a11f61c40efaa5e1055fabae51990b7b1e1aef1074e3fe`  
**Specification Reference:** 37-page Master Project Implementation + Research Blueprint  
**Subsystem:** S2 (Security Gateway, Policy Engine & Cloud Subsystem)  
**Date:** 2026-11-21  
**UI Integrity Status:** 100% Preserved (Git Tree Hash: `93c66df806ba3ec1aedf888cfd853a7d50858583`)

---

## 1. Executive Summary & Objective

This document establishes the formal, immutable baseline freeze for all seven comparative strategies (B1–B7) and experiment-facing configurations within the QERIS S2 Gateway. 

The primary research contribution of QERIS is:
> **Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes.**

To defensibly evaluate this contribution against standard industry practices and academic alternatives, S2 provides centralized configuration, deterministic RFC 8785 canonical digest verification, strict state isolation, and explicit API controls. Every baseline executes through the same operational pipeline, ingesting common traffic structures while maintaining distinct behavioral properties.

---

## 2. Authoritative Definitions of Baselines B1–B7

Each baseline is implemented, documented, and frozen in accordance with the Master Project Blueprint and Table 1:

| ID | Name | Master Blueprint Definition | Fixed Mode | Floor Enforced? | S3 Cause Classification? | Adaptive MTU / Recovery Hints? | Security Floor Violations |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| **B1** | **Static Classical** | Legacy ECDH key exchange only. Rejects non-classical requests and flows requiring higher floors. | `CLASSICAL` | **Yes** | No | No | **0.0%** (Rejects flows > Classical) |
| **B2** | **Static Hybrid** | Fixed X25519 + ML-KEM. Rejects non-hybrid requests and flows requiring pure PQC. | `HYBRID` | **Yes** | No | No | **0.0%** (Rejects Critical flows) |
| **B3** | **Static PQC** | Fixed pure ML-KEM. Rejects requests below PQC; fails constrained devices unable to support PQC memory/MTU. | `PQC` | **Yes** | No | No | **0.0%** (Rejects constrained devices) |
| **B4** | **Sensitivity-Only** | Enforces policy floor strictly by sensitivity tier, but disables all cause-classified recovery adaptations. | None | **Yes** | No | No | **0.0%** (Aborts on first network failure) |
| **B5** | **Downgrade-on-Failure** | Naive industry fallback that steps down crypto mode to maintain connectivity upon failure, violating security floors. | None | **No** (Violates) | Bypassed | No | **60.0%** (Permits Classical under attack/fault) |
| **B6** | **Static Retry with Floor** | Retries blindly at required floor without classifying fault cause or adapting packet size. | None | **Yes** | No | No | **0.0%** (Retries blindly until timeout) |
| **B7** | **Full QERIS Gateway** | Dynamic signed policy floor, pure readiness, S3 cause-classified recovery, adaptive MTU fragmentation, DEC-4 epoch guards. | Dynamic | **Yes** | **Yes** | **Yes** | **0.0%** (Guaranteed mathematical floor bound) |

---

## 3. Configuration & Selection Mechanism

### 3.1 Centralized Configuration (`GatewayConfig`)
Gateway operations and baseline parameters are centralized in `qeris/s2/config.py` under the `GatewayConfig` class. The configuration is hashed using RFC 8785 canonical JSON sorting and UTF-8 encoding:

- **Config Version:** `2.0.0-frozen`
- **Default Authority ID:** `QERIS-GATEWAY-AUTH-01`
- **Signature Algorithm:** `ML-DSA-65` (NIST FIPS 204)
- **Rate Limiting:** Token Bucket (Capacity: 10.0, Refill Rate: 2.0 tokens/s)
- **Cloud Forwarding Queue:** Bounded FIFO (Max Size: 1000, Timeout: 2.0s)
- **Default Operational Baseline:** `BaselineMode.FULL_GATEWAY`

### 3.2 Dynamic Mode Selection API
Baselines are selectable exclusively through explicit, validated admin requests:
- **Endpoint:** `POST /api/v1/admin/baseline`
- **Payload Schema:**
  ```json
  {
    "baseline_mode": "static_classical" | "static_hybrid" | "static_pqc" | "sensitivity_only" | "downgrade_on_failure" | "static_retry_with_floor" | "full_gateway",
    "run_id": "optional_experiment_run_id",
    "scenario": "optional_scenario_id"
  }
  ```
- **Validation Rule:** Unrecognized or invalid baseline strings are rejected immediately with HTTP 422 Unprocessable Entity. The gateway NEVER silently falls back to an unintended mode.

### 3.3 Discovery Endpoint
- **Endpoint:** `GET /api/v1/admin/baseline`
- Returns active baseline, full description, behavioral recovery properties, and the complete enumeration of available baselines.

---

## 4. State Isolation & B5 Security Containment

### 4.1 Strict Isolation of B5 Downgrades
The Master Blueprint explicitly requires comparing QERIS against naive industry gateways that downgrade cryptographic suites when handshakes fail. 
- In `gateway_service.py`, the downgrade bypass is strictly isolated to:
  ```python
  if current_baseline == BaselineMode.DOWNGRADE_ON_FAILURE:
  ```
- When a downgrade request occurs under B5, the gateway flags `"floor_violation": True`, marks `"downgrade_permitted_experimental": True`, logs the security violation in `gateway_audit.jsonl`, and bypasses the S3 Downgrade Rejector.
- Under all other baselines (B1–B4, B6, and B7), this bypass is completely unreachable. In `FULL_GATEWAY`, strict floor enforcement (`req_rank >= floor_rank`) and S3 defense-in-depth hooks are 100% active.

### 4.2 State Reset API between Experiment Runs
To prevent state contamination across sequential experiment runs (such as token bucket exhaustion or active session context overlap):
- **Endpoint:** `POST /api/v1/admin/reset`
- **Payload:**
  ```json
  {
    "reset_rate_limits": true,
    "clear_sessions": true,
    "reset_baseline": "full_gateway",
    "run_id": "run_cleanup_01"
  }
  ```
- **Execution:** Wipes token bucket caches via `_rate_limiter.clear()`, clears active session mappings via `_session_mgr.clear()`, restores default operational baseline `FULL_GATEWAY`, and emits an audit event.

---

## 5. S4 Evaluation Compatibility Contract (S2 Boundary)

S2 provides a clean, decoupled boundary for S4's benchmark evaluation runner:

1. **Common Request Ingestion:** S4 sends traffic to `POST /check-flow` or `POST /api/v1/handshake/initiate`.
2. **Context Propagation:** Requests accept optional `run_id` and `scenario` fields. S2 echoes these parameters in response payloads and writes them to every audit log entry.
3. **Structured Response Contracts:**
   - `baseline_mode`: Active baseline executing the request.
   - `adaptive_recovery`: Boolean flag indicating whether cause-classified recovery hints are active (`True` only in B7).
   - `floor_violation`: Boolean flag indicating whether a security floor violation occurred (`True` only in B5 downgrade).
   - `decision`: Authoritative decision (`ALLOW`, `REJECT`).
   - `s3_verdict`: S3 hook outcome (`PERMIT`, `DISCARD_AND_LOG`, `BYPASSED_FOR_BASELINE`).
4. **Structured Audit Logging:** S4 can parse raw audit records from `gateway_audit.jsonl` or query `GET /api/v1/admin/audit-logs?limit=N`. All logs include millisecond timestamps, run IDs, scenario tags, and redacting secret keys.

---

## 6. Categorical Verification Classification

Every baseline and supporting component is classified according to actual repository evidence:

| Component / Subsystem | Implementation Status | Test Coverage | Operational Classification |
|---|---|---|---|
| **B1 (Static Classical)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B2 (Static Hybrid)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B3 (Static PQC)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B4 (Sensitivity-Only)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B5 (Downgrade-on-Failure)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B6 (Static Retry with Floor)** | Fully Implemented in `gateway_service.py` | `test_baselines_b1_b7.py`, `test_baseline_freeze.py` | **SMOKE-TESTED & FROZEN** |
| **B7 (Full QERIS Gateway)** | Fully Implemented across S1, S2, S3, S4 | `test_baselines_b1_b7.py`, `test_s4.py`, `test_end_to_end.py` | **EXPERIMENTALLY EVALUATED & FROZEN** |
| **Anti-Rollback Policy Store** | Fully Implemented (`policy_store.py`) | `test_policy_store_anti_rollback.py` | **INTEGRATION-TESTED & FROZEN** |
| **Deterministic Readiness** | Fully Implemented (`readiness.py`) | `test_capability_readiness.py` | **INTEGRATION-TESTED & FROZEN** |
| **DEC-4 Session Epochs** | Fully Implemented (`session_manager.py`) | `test_session_epoch_dec4.py` | **INTEGRATION-TESTED & FROZEN** |
| **Cloud Outage Queue** | Fully Implemented (`cloud_client.py`) | `test_cloud_pipeline_and_outage.py` | **INTEGRATION-TESTED & FROZEN** |
| **Docker Compose Services** | Structurally Complete (`docker-compose.yml`) | Structural YAML/Dockerfile analysis | **STRUCTURALLY VALID / RUNTIME UNVERIFIED** |
| **Physical ESP32 Microcontrollers** | Firmware calibration protocol defined | N/A (Software emulation in repo) | **NOT VERIFIED (FUTURE HIL WORK)** |

---

## 7. Change Management & Governance

1. **Frozen Parameters:** No changes to `BASELINE_RECOVERY_PROPERTIES`, `MODE_RANK`, `MINIMUM_FLOOR_MAP`, or `GatewayConfig` defaults are permitted without recalculating and recording a new configuration digest in this document.
2. **Approved Modifications:** Any modification to S2 baseline behavior requires:
   - Re-running the 278-test regression suite.
   - Updating the canonical digest in `BASELINE_FREEZE.md`.
   - Regenerating `qeris/s2/evidence/baseline_freeze_evidence.json`.
3. **S4 Scope Separation:** S4 owns the experiment execution matrix, statistical hypothesis testing (Welch's t-test, Mann-Whitney U, Wilson score CIs), publication tables, and plotting scripts. S2 remains the strictly unopinionated execution runtime.
