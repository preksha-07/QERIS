# QERIS S2: API Specification and Protocol Contracts

## 1. Gateway Public & Device APIs

### 1.1 `POST /check-flow`
Evaluates whether a device request satisfies the signed policy floor and readiness constraints. Supports existing UI and S1/S3/S4 integration contracts.

- **Request Body:**
  ```json
  {
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "requested_mode": "PQC",
    "requested_profile": "PQC_MLKEM512_AESGCM",
    "device_reported_sensitivity": null
  }
  ```
- **Response (200 OK - Allowed):**
  ```json
  {
    "decision": "ALLOW",
    "reason": "Policy and readiness criteria satisfied",
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "sensitivity": "CRITICAL",
    "minimum_mode": "PQC",
    "approved_security_profiles": ["PQC_MLKEM512_AESGCM", "PQC_MLKEM768_AESGCM"],
    "selected_security_profile": "PQC_MLKEM512_AESGCM",
    "policy_version": 1,
    "policy_digest": "4c45b...",
    "authority_id": "QERIS-GATEWAY",
    "readiness": {
      "status": "READY",
      "feasible_profiles": ["PQC_MLKEM512_AESGCM"],
      "recommended_profile": "PQC_MLKEM512_AESGCM",
      "reasons": ["Device and flow meet all criteria"]
    },
    "s3_verdict": "PERMIT"
  }
  ```
- **Response (403 Forbidden - Downgrade Blocked):**
  ```json
  {
    "decision": "REJECT",
    "reason": "Requested mode 'CLASSICAL' (rank 1) is below signed security floor 'PQC' (rank 3)",
    "sensitivity": "CRITICAL",
    "minimum_mode": "PQC",
    "policy_version": 1,
    "policy_digest": "4c45b...",
    "s3_verdict": "DISCARD_AND_LOG"
  }
  ```
- **Response (429 Too Many Requests - Rate Limited):**
  ```json
  {
    "decision": "REJECT",
    "reason": "Per-device rate limit exceeded",
    "retry_after": 2.5
  }
  ```

---

### 1.2 `POST /api/v1/handshake/complete`
Completes cryptographic session establishment and binds session context to the active policy epoch.

- **Request Body:**
  ```json
  {
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "negotiated_profile": "PQC_MLKEM512_AESGCM",
    "session_key_hex": "optional_pre_shared_or_kem_derived_hex"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "status": "SESSION_ACTIVE",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "sensitivity": "CRITICAL",
    "negotiated_profile": "PQC_MLKEM512_AESGCM",
    "policy_version": 1,
    "policy_digest": "4c45b...",
    "policy_epoch": 1
  }
  ```

---

### 1.3 `POST /api/v1/telemetry`
Receives telemetry payload, verifies DEC-4 epoch freshness, validates AEAD envelope if encrypted, and forwards to Cloud API.

- **Request Body:**
  ```json
  {
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "payload": {
      "temperature": 23.4,
      "valve_state": "OPEN"
    },
    "encrypted_envelope_hex": null
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "status": "ACCEPTED",
    "event_id": "c1a2e3f4-...",
    "device_id": "dev_001",
    "flow_id": "emergency_stop",
    "sensitivity": "CRITICAL",
    "cloud_delivery": "FORWARDED_TO_CLOUD",
    "queue_size": 0
  }
  ```

---

## 2. Gateway Administrative APIs

### 2.1 `POST /api/v1/admin/policy`
Installs an ML-DSA-65 signed policy envelope into persistent SQLite storage.

- **Request Body:**
  ```json
  {
    "policy": {
      "authority_id": "QERIS-GATEWAY",
      "policy_version": 2,
      "policies": {
        "emergency_stop": {
          "flow_id": "emergency_stop",
          "device_scope": ["*"],
          "sensitivity": "CRITICAL",
          "minimum_mode": "PQC",
          "approved_security_profiles": ["PQC_MLKEM512_AESGCM"]
        }
      }
    },
    "policy_digest": "sha256_hex_digest...",
    "sig_alg": "ML-DSA-65",
    "signature": "mldsa65_hex_signature..."
  }
  ```
- **Rejection Responses:**
  - `400 Bad Request` with `status: "ROLLBACK_REJECTED"` if `version < highest_version`.
  - `400 Bad Request` with `status: "INVALID_SIGNATURE"` if tampered.
  - `400 Bad Request` with `status: "UNTRUSTED_AUTHORITY"` if unknown authority.

---

### 2.2 Device & Registry APIs
- `GET /api/v1/admin/devices`: Lists enrolled device profiles.
- `POST /api/v1/admin/devices`: Registers new device profile.
- `POST /api/v1/admin/devices/{device_id}/quarantine`: Quarantines device.

---

## 3. Cloud Telemetry APIs (`port 8001`)

- `POST /api/v1/cloud/ingest`: Ingests forwarded telemetry from gateway.
- `GET /api/v1/cloud/telemetry`: Queries telemetry with flow and sensitivity filters.
- `GET /api/v1/cloud/telemetry/{event_id}`: Fetches specific telemetry record.
- `GET /api/v1/cloud/stats`: Aggregated metrics by flow and sensitivity tier.
- `GET /api/v1/cloud/health`: Cloud database and service health check.
