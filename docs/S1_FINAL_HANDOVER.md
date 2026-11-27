# QERIS S1 — Cryptography & Device Final Handover

**Subsystem:** S1 (Cryptography and Device)
**Date:** 2026-11-23
**Status:** S1 Core Primitives & Simulation Complete; Hardware Verification Blocked on Board Access
**Test Baseline:** 90 passed, 12 subtests passed (0 failures, 0 errors)

---

## 1. S1 Architecture & Cryptographic Primitives

S1 provides the post-quantum and classical cryptographic building blocks, canonical serialization, device authentication, and local simulation layers for QERIS:

| Component | Module | Primitives & Standards | Responsibility |
|---|---|---|---|
| **Session Crypto** | [`session_crypto.py`](../qeris/session_crypto.py) | ML-KEM-512 (FIPS 203), HKDF-SHA256 (RFC 5869), SHA-256 (FIPS 180-4) | Keypair generation, encapsulation, decapsulation, context-bound session key derivation, and canonical transcript hash (`handshake_id`). |
| **Secure Message** | [`secure_message.py`](../qeris/secure_message.py) | AES-256-GCM (NIST SP 800-38D) | Authenticated telemetry encryption with 96-bit monotonic counter, context-bound AAD, and replay/out-of-order rejection. |
| **Device Authentication** | [`device_auth.py`](../qeris/device_auth.py) | Ed25519 (RFC 8032), SHA-256 | Long-term device proof of possession, canonical context-bound message framing, and gateway freshness challenge management. |
| **Policy Authority** | [`policy/signed_policy.py`](../qeris/policy/signed_policy.py)<br>[`policy/offline_signer.py`](../qeris/policy/offline_signer.py)<br>[`policy/serialization.py`](../qeris/policy/serialization.py) | ML-DSA-65 (FIPS 204), Canonical JSON | Canonical 5-field schema validation, domain-separated signing (`b"QERIS-POLICY-v1\x00"`), envelope serialization, and offline authority CLI. |
| **Device Simulator** | [`device_simulator.py`](../qeris/device_simulator.py) | ML-KEM-512, X25519, Ed25519, AES-256-GCM | Local in-process round-trip orchestration for `PQC` and `CLASSICAL` profiles, synthetic delay/timeout injection, and S1 failure hooks. |

---

## 2. Simulator Profiles (PQC & Classical)

The device simulator ([`device_simulator.py`](../qeris/device_simulator.py)) supports two explicit operational profiles via `DeviceProfile`:

- **`DeviceProfile.PQC` (Default):**
  - Key Establishment: ML-KEM-512 (800-byte public key, 768-byte ciphertext).
  - KDF: HKDF-SHA256 bound to `device_id`, `flow_id`, `sensitivity_tier`, and `policy_version`.
  - Transcript: Deterministic 64-character hex `handshake_id` from the KEM transcript hash.
  - AEAD: AES-256-GCM telemetry message encryption.
- **`DeviceProfile.CLASSICAL`:**
  - Key Agreement: Ephemeral X25519 (32-byte public keys, RFC 7748) via [`qeris_classical.session_crypto`](../../../qeris_classical/session_crypto.py).
  - KDF: HKDF-SHA256 with identical context binding.
  - Transcript: Deterministic 64-character hex correlation hash over both ephemeral public keys and context.
  - AEAD: Shared AES-256-GCM telemetry message encryption.
- **Hybrid Mode Status:**
  - `DeviceProfile.HYBRID` is implemented in the local in-process simulator as X25519MLKEM768 (X25519 + ML-KEM-768). It uses RFC 9958 concatenated hybrid key-agreement approach with RFC 10024 component-share ordering. It is not a TLS 1.3 / DTLS 1.3 implementation and does not claim wire-protocol interoperability. See `S1_HYBRID_PROFILE.md`.

---

## 3. Ed25519 Device Authentication & Gateway Boundary

Device identity is decoupled from ephemeral session key establishment (DEC-1):

- **Cryptographic Mechanics:**
  - Long-term 32-byte raw Ed25519 public key enrolled out-of-band; 64-byte signature.
  - Canonical message formatting binds `device_id`, `handshake_id` (transcript hash), gateway freshness challenge (32 random bytes), and integer timestamp under domain label `b"QERIS-DEVICE-AUTH-v1\x00"`.
  - Rejects malformed IDs, non-integer timestamps, and incorrect challenge lengths before signing.
  - Confidentiality: private keys are never exposed in `__repr__`, `__str__`, or serialization.
- **Gateway Freshness & Replay Prevention:**
  - `GatewayChallengeManager` generates 32-byte cryptographically secure random challenges with configurable TTL (default 60s).
  - Enforces single-use consumption: replayed challenges return `AUTH_CHALLENGE_REPLAYED`.
  - Enforces device binding: mismatched device returns `AUTH_MALFORMED`.
- **S1 vs. S2 Responsibility Boundary:**
  - **S1 Scope:** Implements device-side key custody, message framing, challenge signing, and reference challenge manager. `SimulatedDevice` reports `device_authentication_status="SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED"`.
  - **S2 Gateway Scope:** S2 owns the device registry (`devices.json`), revocation list enforcement, persistent/multi-worker challenge state coordination, and final admission authorization (`ALLOW`). Ephemeral KEM agreement or device signature alone is not gateway admission.

---

## 4. Offline ML-DSA-65 Policy Signing & Five-Field Schema

S1 implements the canonical five-field policy schema and offline authority tooling:

- **Canonical Five-Field Schema:**
  - `flow_id`: non-empty string.
  - `sensitivity`: `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"`.
  - `minimum_mode`: `"CLASSICAL"`, `"HYBRID"`, `"PQC"`, or `"PQ"`.
  - `policy_version`: integer >= 1 (strictly not boolean).
  - `authority_id`: non-empty string resolved against trusted authority registry.
- **Envelope Decoupling:**
  - Outer envelope stores metadata: `{"policy": {...}, "sig_alg": "ML-DSA-65", "signature": "<hex>"}`.
  - Signature covers domain-separated canonical bytes: `b"QERIS-POLICY-v1\x00" || serialize_policy_to_bytes(policy)`.
- **Anti-Rollback Order of Operations:**
  - Cryptographic signature and structure are verified *before* anti-rollback evaluation.
  - Forged stale policies fail with `INVALID_SIGNATURE`; authentic stale policies fail with `STALE_POLICY`.
- **Offline Authority CLI ([`policy/offline_signer.py`](../qeris/policy/offline_signer.py)):**
  - `genkey`: Generates offline ML-DSA-65 authority keypair atomically with POSIX 0o600 file permissions.
  - `sign`: Validates policy schema, enforces `--authority-id`, and signs envelopes atomically. Refuses overwrite unless `--overwrite` is specified.
  - Operational rule: The gateway only verifies policies; it never signs policies or loads the authority private key at runtime.

---

## 5. AES-256-GCM Nonce Lifecycle & Restart Limitations

- **Nonce Mechanics:**
  - Uses standard 12-byte (96-bit) nonce derived from a strictly increasing counter starting at 0.
  - Nonce exhaustion guard raises `MessageCryptoError` before counter exceeds `(1 << 96) - 1`.
  - Decryptor rejects repeated and out-of-order counters (`ReplayError`).
  - Failed authentication never advances receiver replay state.
  - Context fields (`device_id`, `flow_id`, `sensitivity_tier`, `policy_version`) are length-prefixed and authenticated as AAD.
- **Process-Restart Limitation (Critical Operational Constraint):**
  - The counter is process-local and held in memory only.
  - Upon process restart, reboot, or encryptor recreation, the counter resets to 0.
  - **Security rule:** To prevent catastrophic AES-GCM nonce reuse under the same key, a fresh session key must be established via handshake after every process restart or reboot. Keys must never be reused across restarts or shared across independent encryptor instances.

---

## 6. Simulator Capabilities & Synthetic Delay/Timeout

- **Capabilities:**
  - End-to-end local round-trip execution via `simulate_device_round_trip()`.
  - Custom flow mapping, custom policy version, and payload verification.
  - Exposes non-secret fingerprints and deterministic `handshake_id` on both peers.
- **Synthetic Latency & Timeout Simulation (`SimulatorConfig`):**
  - `compute_delay_seconds`: Injects synthetic compute delay before keypair generation and handshake completion.
  - `timeout_seconds`: Triggers `SimulatorTimeoutError` when simulated delay exceeds the configured threshold.
  - **Limitation:** Compute delays and timeouts are purely synthetic simulation parameters for testing timeout detection and error handling. They are **not** calibrated from real ESP32 hardware measurements.
- **S1 Failure Hook vs. S3 Recovery:**
  - `SimulatorConfig` exposes an optional `on_failure: Callable[[str, Exception], None]` callback.
  - Invoked immediately before re-raising exceptions for logging/observability.
  - S1 does not implement recovery policy or suppress exceptions; all recovery decisions remain strictly owned by S3.

---

## 7. Test & Reproducibility Evidence

The S1 test suite executes cleanly with zero failures or errors:

- **Pass Count:** **90 passed, 12 subtests passed** in 0.71s.
- **Evidence Files:**
  - Execution Log: [`docs/evidence/s1_test_run_20261122.txt`](../../../docs/evidence/s1_test_run_20261122.txt)
  - Environment Record: [`docs/evidence/s1_environment_versions.txt`](../../../docs/evidence/s1_environment_versions.txt)
- **Verified Environment:**
  - Python: 3.13.14 (win32)
  - pytest: 9.2.0 (pluggy 1.7.0, iniconfig 2.3.1)
  - liboqs-python: 0.16.0.1 (native liboqs 0.16.0; ML-KEM-512 and ML-DSA-65 enabled)
  - cryptography: 50.0.2 (cffi 2.1.1, pycparser 3.12)
- **Test Breakdown by Module:**
  - `test_crypto_smoke.py`: 6 passed (ML-KEM-512, ML-DSA-65 sanity)
  - `test_device_auth.py`: 12 passed (Ed25519 credentials, challenges, replay, tampering)
  - `test_device_simulator.py`: 13 passed, 5 subtests (PQC/Classical profiles, delays, timeouts, hooks)
  - `test_offline_signer.py`: 5 passed (key generation, single/bundle signing, overwrite protection)
  - `test_secure_message.py`: 10 passed, 7 subtests (AES-GCM encryption, tampering, replay, context binding)
  - `test_session_crypto.py`: 13 passed (ML-KEM-512 encap/decap, HKDF derivation, `handshake_id`)
  - `test_signed_policy.py`: 31 passed (canonical validation, envelope decoding, anti-rollback)

---

## 8. Hardware-Dependent Items Requiring Physical ESP32

The following items are **unverified** and require physical ESP32 board access and firmware flashing:

1. **ESP32 Firmware:** Real C/ESP-IDF implementation of ML-KEM-512 or Route B primitives on Xtensa LX6 hardware.
2. **E1 Wire-Byte & Fragmentation Measurements:** Real network capture of wire bytes, fragmentation overhead, and MTU boundary behavior across physical interfaces.
3. **G2 ESP32 Calibration Runs:** Measured key-generation latency, handshake duration, free heap, and minimum heap watermarks recorded on physical silicon.
4. **Evidence Status:** No hardware measurement CSVs, logs, or firmware files are present in `docs/evidence/`. Simulator timings must not be misrepresented as real hardware measurements.

---

## 9. S2 / S3 / S4 Integration Dependencies & Open Questions

- **S2 Gateway:**
  - Persistent anti-rollback store: Gateway must maintain durable storage for the highest accepted `policy_version` per flow.
  - Multi-worker challenge coordination: Reference `GatewayChallengeManager` is in-memory; production multi-worker deployment requires durable or shared single-use challenge consumption.
  - Device registry enrollment: Register device Ed25519 public keys in `devices.json` and enforce status checks (active/revoked/quarantine).
- **S3 Security & Recovery:**
  - Map S1 failure exceptions (`AuthenticationError`, `ReplayError`, `SimulatorTimeoutError`, `CryptoInputError`) to S3 failure taxonomy cause classes.
  - State machine must enforce security floors and never lower floors on failure.
- **S4 Evaluation & Analytics:**
  - Reconcile transport MTU and fragmentation budgets with S1's 1 MiB defensive envelope cap.
  - Update `qeris/s4/viva_question_bank.md` to reconcile claims: remove assertions that S1 completed physical ESP32 calibration and that device auth is `NOT_IMPLEMENTED`.
- **Cross-Subsystem:**
  - Hybrid mode: The simulator uses the published X25519MLKEM768 concatenated construction. Full TLS 1.3 / DTLS 1.3 interoperability remains unimplemented and requires a native protocol stack with the group enabled.

---

## 10. S1 Completion Checklist

- [x] ML-KEM-512 keypair generation, encapsulation, and decapsulation implemented and tested.
- [x] HKDF-SHA256 context-bound session key derivation implemented and tested.
- [x] Canonical transcript hash (`handshake_id`) exposed on both peers.
- [x] AES-256-GCM authenticated message encryption with 96-bit monotonic counter implemented and tested.
- [x] Canonical five-field policy schema validation implemented and tested.
- [x] ML-DSA-65 policy envelope signing and domain separation (`b"QERIS-POLICY-v1\x00"`) verified.
- [x] Offline policy authority CLI (`offline_signer.py`) implemented, tested, and documented.
- [x] Ed25519 long-term device authentication and gateway freshness challenge replay protection implemented and tested.
- [x] Device simulator supporting `PQC` and `CLASSICAL` profiles implemented and tested.
- [x] Synthetic compute delay and timeout simulation with S1 failure hook implemented and tested.
- [x] Replay, tamper, malformed input, and context-mismatch rejection verified across all primitives.
- [x] Zero secrets (private keys, shared secrets, plaintexts) exposed in logs, exceptions, `repr`, or `str`.
- [x] Test execution record and environment versions captured in `docs/evidence/`.
- [x] Documentation updated and verified consistent across S1 documents.
- [ ] Physical ESP32 firmware and hardware calibration (E1/G2) — *Blocked pending hardware access*.
- [x] In-process Hybrid simulator profile — *X25519MLKEM768 component shares and concatenated shared-secret construction implemented; TLS/DTLS transport interoperability remains out of scope for this simulator*.
