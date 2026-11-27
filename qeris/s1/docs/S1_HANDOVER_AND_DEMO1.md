# QERIS S1 handover and Demo 1 readiness

Last reviewed: 2026-11-22

## 1. Demo 1 goal

Demo 1 is the gateway working-flow demonstration:

1. A device submits a LOW-sensitivity flow.
2. The gateway loads the policy.
3. The gateway verifies the policy using a trusted authority public key.
4. The gateway checks the flow's required minimum security mode and the device's registered capability.
5. The request satisfies those checks, so the gateway returns `ALLOW` and records an audit event.

S1 is responsible for the cryptographic components, device simulator, and their contract. S2 owns the gateway integration. The local S1 simulator is not itself proof that this end-to-end gateway demo works.

## 2. S1 code present

| File | Current responsibility | Readiness |
|---|---|---|
| `qeris/policy/serialization.py` | Deterministic canonical JSON serialization and domain separation (`b"QERIS-POLICY-v1\x00"`) | Complete; standardized |
| `qeris/policy/signed_policy.py` | ML-DSA-65 signing/verification and canonical 5-field schema validation | Complete; aligned with S2 schema |
| `qeris/policy/offline_signer.py` | Offline authority keypair generation and policy envelope signing CLI | Complete; operational |
| `qeris/session_crypto.py` | ML-KEM-512, HKDF-SHA256, and canonical `handshake_id` transcript hash | Complete; tested |
| `qeris/device_auth.py` | Ed25519 device credentials, gateway freshness challenge manager, and canonical message binding | Complete; tested |
| `qeris/secure_message.py` | AES-256-GCM envelope, AAD context binding, monotonic counter replay rejection | Complete; tested |
| `qeris/device_simulator.py` | In-process simulator supporting `PQC` (ML-KEM-512) and `CLASSICAL` (X25519) profiles, synthetic delay/timeout, and Ed25519 signing | Complete; local simulation only |

## 3. Policy schema alignment

The policy schema is standardized on S2's canonical five-field representation:

`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`.

Signatures are decoupled in an explicit outer envelope:
- `policy`: the canonical five-field object.
- `sig_alg`: `ML-DSA-65`.
- `signature`: hex-encoded signature over `b"QERIS-POLICY-v1\x00" || canonical_policy_bytes`.

### Contract rules
1. **Signed object:** Explicit envelope containing the canonical 5-field policy mapping.
2. **Signature metadata:** `sig_alg` allowlisted (default: `ML-DSA-65`).
3. **Domain separation:** Fixed prefix `b"QERIS-POLICY-v1\x00"` prepended to canonical bytes before signing and verification.
4. **Authority lookup:** Gateway maps `authority_id` to a trusted preconfigured public key. Unregistered authorities reject (`UNTRUSTED_AUTHORITY`).
5. **Anti-rollback:** Evaluated strictly *after* cryptographic signature verification proves authentic origin. Persistent version store is owned by S2.
6. **Offline authority:** The gateway only verifies policies; it never signs policies or loads the authority private key at runtime. Signing is performed offline via `offline_signer.py`.

## 4. Cryptographic contracts

### ML-KEM-512 & Classical X25519
- Approved PQC KEM: ML-KEM-512 (FIPS 203).
- Ephemeral Classical key agreement: X25519 (RFC 7748).
- HKDF-SHA256 derives a 32-byte key using length-prefixed context: `device_id`, `flow_id`, `sensitivity_tier`, and `policy_version`.
- Ephemeral key agreement establishes a shared secret; it does not authenticate a device identity. Long-term device authentication is provided separately via Ed25519.
- Do not log private keys, shared secrets, session keys, or plaintext.

### Ed25519 Device Authentication
- Long-term 32-byte Ed25519 key enrolled out-of-band.
- Signs canonical message binding `device_id`, `handshake_id` (transcript hash), gateway freshness challenge, and timestamp under domain label `b"QERIS-DEVICE-AUTH-v1\x00"`.
- Gateway issues 32-byte random freshness challenge, enforces TTL, and marks challenge consumed (single-use).

### AES-GCM message protection
- AES-256-GCM with a 32-byte derived session key.
- Context authenticated as AAD: `device_id`, `flow_id`, `sensitivity_tier`, and `policy_version`.
- Monotonically increasing 96-bit counter as nonce.
- Receiver rejects repeated and out-of-order counters.
- **Reboot safety:** The counter is in-memory only and resets upon restart. To prevent nonce reuse, a fresh session key must be established via handshake after every reboot. A session key must never be reused across encryptor instances or restarts.
- Maximum envelope size: 1 MiB defensive prototype limit.

## 5. Simulator capabilities and explicit boundaries

`qeris/device_simulator.py`:
- Supports `DeviceProfile.PQC` (ML-KEM-512) and `DeviceProfile.CLASSICAL` (X25519).
- **Hybrid mode:** `HYBRID` is available in the in-process simulator as X25519MLKEM768 (X25519 + ML-KEM-768). It is not TLS/DTLS interoperable; see `S1_HYBRID_PROFILE.md`.
- **Synthetic delay/timeout:** `compute_delay_seconds` and `timeout_seconds` in `SimulatorConfig` are synthetic parameters for testing timeout paths and failure hooks; they are NOT calibrated from hardware measurements.
- Reports `authorization_decision=NOT_PERFORMED` (authorization belongs to gateway).
- Reports `device_authentication_status=SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED` (device signs challenge with Ed25519 credential; gateway registry verification and admission belong to S2).

## 6. Test and evidence checklist

### Verified S1 crypto checks
- [x] ML-KEM-512 keypair/encaps/decaps: device and receiver shared-secret fingerprints match.
- [x] Classical X25519: key agreement and session key derivation match.
- [x] HKDF: same context produces matching keys; changed context produces different derived key.
- [x] ML-DSA-65: valid envelope verifies; tampered policy/signature rejects; domain separation enforced.
- [x] Offline signer: key generation, single-policy signing, bundle signing, overwrite protection.
- [x] Ed25519 device auth: valid signature verifies; tampered signature, mismatched handshake_id, expired challenge, and replayed challenge reject.
- [x] Message protection: round trip succeeds; tampering, wrong context, replay, and out-of-order reject.
- [x] Simulator: PQC round-trip, Classical round-trip, invalid profile rejection, synthetic delay/timeout execution, and S1 failure hooks pass.
- [x] Confidentiality: no private keys or secrets leaked in repr, str, or logs.
- [x] Test suite evidence recorded: **90 passed, 12 subtests passed** in 0.71s (`docs/evidence/s1_test_run_20261122.txt`).
- [x] Environment versions recorded: Python 3.13.14, pytest 9.2.0, liboqs-python 0.16.0.1, cryptography 50.0.2 (`docs/evidence/s1_environment_versions.txt`).

### S2 integrated Demo 1 evidence (Gateway ownership)
- [ ] Gateway loads the agreed policy document.
- [ ] Policy signature is checked against the configured trusted authority key.
- [ ] Persistent version state is checked and updated safely.
- [ ] LOW flow resolves to the policy's LOW sensitivity/minimum mode.
- [ ] Registered device capability satisfies the minimum mode.
- [ ] Gateway returns `ALLOW` for the valid request.
- [ ] Audit log records flow/device, policy version, decision and reason without secrets.
- [ ] Invalid signature and stale/rollback policy are rejected in negative tests.

### Hardware validation status (ESP32, E1, G2)
- [ ] ESP32 firmware integration, E1 wire fragmentation data, and G2 calibration data remain **unverified** pending physical board testing. No hardware evidence files exist in `docs/evidence/`.

## 7. Ownership boundaries

- **S1:** crypto APIs, tests, offline signer, key handling notes, simulator profiles/hooks, and reproducibility evidence.
- **S2:** policy schema implementation in gateway, trusted authority lookup, persistent version store, device capability registry, gateway decision and audit logging, integration demo.
- **S3:** threat model, security-floor invariant monitor, downgrade/replay tests, failure taxonomy and recovery controller.
- **S4:** log parser, experiment runner, fault injection, statistics and result plots.
