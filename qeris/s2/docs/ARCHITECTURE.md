# QERIS S2: Gateway and Cloud Architecture Specification

## 1. System Overview

The QERIS S2 Gateway sits between heterogeneous IoT edge devices and backend cloud services, acting as a trusted cryptographic enforcement and migration boundary.

The core research contribution is:
**Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes.**

```
+---------------+           TB1           +-----------------------+           TB2           +-------------------+
|  IoT Device   | ======================> | QERIS Security Gateway| ======================> |   Cloud Service   |
| (ESP32/Edge)  |   (Device/GW Session)   |  - Policy Enforcement |  (Gateway/Cloud TLS)   | (FastAPI + SQLite)|
+---------------+                         |  - Anti-Rollback Store|                         +-------------------+
                                          |  - Capability Registry|
                                          |  - S3 FSM Hook        |
                                          |  - Outage Queue       |
                                          +-----------------------+
                                                      ^
                                                      | TB3 (ML-DSA-65 Signed Policy)
                                          +-----------------------+
                                          | Policy Signing Auth   |
                                          | (Offline ML-DSA-65)   |
                                          +-----------------------+
```

## 2. Trust Boundaries

| Boundary | Crossing | Trust Level & Enforcement |
|---|---|---|
| **TB1** | Device to Gateway | Untrusted transport, semi-trusted device. Terminated at gateway. Protected via ML-KEM/AEAD. Device claims (e.g. sensitivity labels) are **NEVER trusted**. |
| **TB2** | Gateway to Cloud | Untrusted network. Separate TLS connection. Gateway unpacks accepted device data, validates context, and forwards to Cloud API. |
| **TB3** | Policy Authority to Gateway | Untrusted distribution channel. Authenticated exclusively via FIPS 204 ML-DSA-65 post-quantum digital signatures. |
| **TB4** | Admin/Registry to Gateway | Gateway-registered capabilities. Persisted in SQLite. Capabilities are **NOT hardware-attested**. |

> **Important Boundary Rule:** The gateway terminates the device-side protected session and opens a separate cloud session. QERIS does not claim end-to-end confidentiality between device and cloud. Plaintext exists inside the trusted gateway computing boundary.

## 3. Core Subsystems

### 3.1 Signed Policy System
- Policies are canonically encoded (RFC 8785) UTF-8 JSON with sorted keys and compact separators.
- Signed using NIST FIPS 204 ML-DSA-65.
- SHA-256 digest calculated with domain separation: `QERIS-POLICY-v1:`.
- Policy floor is represented using `approved_security_profiles` set rather than a simple scalar mode.

### 3.2 Persistent Anti-Rollback Policy Store
- SQLite transactional storage (`policy_store.db`).
- Monotonic version check: incoming version <= highest accepted version is rejected (with idempotent exception only for exact duplicate digest).
- In-memory activation occurs **only after** SQLite disk commit succeeds.
- Survives process restart without losing version state.

### 3.3 Gateway Capability Registry & Readiness Engine
- Tracks gateway-registered device capabilities (`device_registry.db`).
- Deterministic, transparent readiness classification (READY, PARTIALLY_READY, NOT_READY).
- Absolutely NO AI/ML is used in readiness.
- `NOT_READY` strictly blocks session activation and **NEVER triggers a downgrade**.

### 3.4 Rate Limiter
- Token-bucket algorithm per `device_id`.
- Configurable capacity (burst) and refill rate.
- Returns HTTP 429 when exhausted; logs audit event. Does not downgrade security.

### 3.5 Session Manager & DEC-4 Policy Epoch Guard
- Tracks session context per `(device_id, flow_id)`.
- When policy updates, in-flight sessions are evaluated against new policy:
  - If profile remains approved: rebound to new epoch.
  - If profile is no longer approved: marked `STALE` and rejected.

### 3.6 Cloud Outage Bounded Queue
- Forwards accepted telemetry to Cloud API (`/api/v1/cloud/ingest`).
- If cloud is unreachable, buffers up to `max_queue_size` (1000 items) in a FIFO queue.
- Rejection/overflow status: `CLOUD_DROPPED_QUEUE_FULL`.
- Automatic retry and flush when cloud recovers.
