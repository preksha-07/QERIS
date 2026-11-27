# S1 Ed25519, Offline Policy Signing, and Simulator Profiles — Change Summary

## Implemented in this package

### Ed25519 device authentication
- Added/retained `Ed25519DeviceCredential` using `cryptography` Ed25519 primitives.
- Uses a 32-byte raw public key and 64-byte signature.
- Uses `DEVICE_AUTH_DOMAIN_SEPARATOR = b"QERIS-DEVICE-AUTH-v1\x00"` (21 bytes).
- Canonically frames device ID, SHA-256 handshake ID, 32-byte gateway challenge, and timestamp before signing.
- Rejects malformed handshake IDs, malformed challenge lengths, and non-integer timestamps.
- Provides gateway challenge issue/expiry/single-use primitives (`GatewayChallengeManager`).
- Integrated a separate Ed25519 credential and challenge-bound signing method into `SimulatedDevice`; the existing X25519/ML-KEM session-establishment code is not replaced.
- Unit coverage for credential handling, signatures, transcript binding, challenge replay/expiry, malformed inputs, and simulator proof-of-possession.

### Offline ML-DSA-65 policy signing
- Added/retained offline key generation and single-policy / multi-flow bundle signing CLI (`offline_signer.py`).
- Enforces canonical five-field policy validation and bundle-key/`flow_id` consistency.
- Enforces an optional requested `authority_id` rather than silently ignoring it.
- Refuses accidental overwrite unless `--overwrite` is explicitly provided.
- Writes generated private keys with owner-only permissions on POSIX and uses atomic file writes.
- Keeps the policy domain-separated signing implementation in `serialization.py` / `signed_policy.py` (`b"QERIS-POLICY-v1\x00"`).
- Offline signer tests and usage documentation included.

### Simulator Profiles & Synthetic Delay/Timeout
- Added `DeviceProfile.PQC` (ML-KEM-512) and `DeviceProfile.CLASSICAL` (X25519) profiles.
- `Hybrid` mode is available in the in-process simulator as X25519MLKEM768 using the RFC 9958 concatenated hybrid key-agreement approach and RFC 10024 component ordering; it is not a TLS/DTLS implementation.
- Added `SimulatorConfig` supporting configurable `compute_delay_seconds` and `timeout_seconds` for testing timeout detection. Delays and timeouts are synthetic test parameters, not calibrated from hardware.
- S1 failure hook interface (`on_failure` callback) exposed for observability; all recovery policy decisions remain owned by S3.

## Verification performed in this environment

- Python 3.13.14 on Windows (win32).
- `liboqs-python==0.16.0.1` (native liboqs 0.16.0 with ML-KEM-512 and ML-DSA-65 enabled).
- `cryptography==50.0.2`.
- Full S1 test suite execution (`pytest qeris/s1/tests/ -v --tb=short`): **90 passed, 12 subtests passed** in 0.71s.
- Detailed execution log saved to `docs/evidence/s1_test_run_20261122.txt`.
- Environment and library record saved to `docs/evidence/s1_environment_versions.txt`.

## Explicit boundaries / remaining integration verification

- `GatewayChallengeManager` is process-local reference state. Multi-worker/restart-safe challenge storage and atomic challenge consumption belong to gateway integration and must be verified there.
- S1 simulator signing proves device-side proof-of-possession construction; it does not by itself prove gateway registry enrollment, revocation, or HTTP integration.
- **AES-GCM Nonce Reboot Safety:** Nonce counter is in-memory only and resets to 0 upon process restart. A fresh session key must be established via handshake after every reboot to prevent nonce reuse.
- **Hardware validation status:** ESP32 hardware measurements, E1 wire fragmentation data, and G2 calibration data remain unverified pending physical hardware testing. No hardware evidence files exist in `docs/evidence/`.
- The gateway/runtime subsystem was not modified in this S1-only task.
- X25519 classical key agreement remains intact and separate from Ed25519 authentication.

## Secret-key handling warning

Private keys must never be committed or shared. If any authority private key was ever exposed, rotate it through the approved authority-key process, update trusted public-key configuration in the gateway, and re-sign affected policies.
