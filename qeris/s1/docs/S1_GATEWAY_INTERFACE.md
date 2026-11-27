# S1 → S2 gateway interface contract

Status: **Aligned interface contract**. S1 provides the cryptographic primitives, canonical schemas, and device simulator; S2 owns gateway integration, persistent anti-rollback storage, and authorization policy enforcement.

## Required inputs to S1 crypto/session path

- `device_id`: registry-resolved identity string; authentication/registry decision is made by gateway.
- `flow_id`: requested flow identifier; sensitivity and minimum mode come from the verified gateway policy, not from a device-supplied tier.
- `sensitivity`: gateway-resolved policy value.
- `policy_version`: version of the verified policy used to authorize this session.
- `session_key`: 32-byte key derived by the approved session-establishment path; must not be logged.

## Handshake Transcript & `handshake_id`

To uniquely correlate cryptographic handshakes across gateway logs (S2) and evaluation pipelines (S4) without exposing secret material, S1 defines a canonical handshake transcript hash exposed as `handshake_id`.

### Transcript Fields
1. **Domain Label:** `b"QERIS-HANDSHAKE-TRANSCRIPT-v1"` (domain separation tag).
2. **Device Ephemeral Public Key:** `device_public_key` (800 bytes for ML-KEM-512, length-prefixed).
3. **KEM Ciphertext:** `ciphertext` (768 bytes for ML-KEM-512, length-prefixed).
4. **Canonical Handshake Context:** Context info containing length-prefixed UTF-8 strings (`device_id`, `flow_id`, `sensitivity_tier`) and big-endian 64-bit integer (`policy_version`), prefixed by `b"QERIS-SESSION-KEY-v1"`.

Private keys and the KEM shared secret are strictly excluded from the transcript.

### Encoding
The transcript fields are framed unambiguously using big-endian 32-bit length prefixes (`>I`):
```
transcript = HANDSHAKE_TRANSCRIPT_LABEL (bytes)
             || uint32_be(len(public_key)) || public_key
             || uint32_be(len(ciphertext)) || ciphertext
             || uint32_be(len(context_info)) || context_info
```

### Hash Algorithm & Format
- **Hash Algorithm:** SHA-256 (FIPS 180-4).
- **Format:** `handshake_id` is exposed as a 64-character lowercase hexadecimal string (`hashlib.sha256(transcript).hexdigest()`).
- Raw 32-byte digest is also available via `compute_transcript_hash(...)`.

### Intended Use
- Correlate the specific KEM exchange between the device and gateway.
- Stable correlation key for S2 gateway audit logs, S3 security monitoring, and S4 analytics without exposing key material.
- Verifiable by both device and gateway since both possess the ephemeral public key, ciphertext, and session context.

## Policy verification boundary

Before a policy is used to authorize a request, the gateway must:

1. Parse the agreed policy envelope strictly.
2. Resolve `authority_id` through a trusted configured key mapping.
3. Verify the signature over the exact canonical bytes with an allowlisted ML-DSA algorithm (`ML-DSA-65`) using domain separation `b"QERIS-POLICY-v1\x00"`.
4. Validate policy fields and allowed values against the canonical five-field schema (`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`).
5. Check persistent version/replay state owned by S2 (anti-rollback).
6. Only then use `minimum_mode` for the flow decision.

A successful ML-KEM operation is not authorization. A valid policy signature is not device authentication.

## Suggested decision reason vocabulary

Use stable machine-readable reason codes where practical; exact names should match S2's existing API/log schema:

- `ALLOW`
- `UNKNOWN_FLOW`
- `UNKNOWN_DEVICE`
- `POLICY_SIGNATURE_INVALID`
- `POLICY_AUTHORITY_UNTRUSTED`
- `POLICY_STALE`
- `POLICY_SCHEMA_INVALID`
- `BELOW_SECURITY_FLOOR`
- `DEVICE_CAPABILITY_INSUFFICIENT`
- `CRYPTO_NEGOTIATION_FAILED`
- `MESSAGE_AUTHENTICATION_FAILED`
- `REPLAY_REJECTED`

Do not collapse cryptographic/security failures into a transport-failure category. Recovery logic must never lower the signed minimum security floor.

## S1 module contract

- `qeris.session_crypto.generate_keypair()` → `(public_key: bytes, secret_key: bytes)`.
- `qeris.session_crypto.encapsulate(public_key)` → `(ciphertext: bytes, shared_secret: bytes)`.
- `qeris.session_crypto.decapsulate(ciphertext, secret_key)` → `shared_secret: bytes`.
- `qeris.session_crypto.derive_session_key(shared_secret, *, device_id, flow_id, sensitivity_tier, policy_version)` → 32-byte session key.
- `qeris.session_crypto.compute_handshake_id(public_key, ciphertext, *, device_id, flow_id, sensitivity_tier, policy_version)` → 64-character hex string `handshake_id`.
- `qeris.session_crypto.compute_transcript_hash(public_key, ciphertext, *, device_id, flow_id, sensitivity_tier, policy_version)` → 32-byte SHA-256 digest.
- `qeris.session_crypto.encode_handshake_transcript(...)` → raw canonical transcript bytes.
- `qeris.secure_message.MessageEncryptor(key, MessageContext(...)).encrypt(plaintext)` → authenticated envelope bytes.
- `qeris.secure_message.MessageDecryptor(key, same_context).decrypt(envelope)` → plaintext bytes or a typed exception.
- `qeris.policy.verify_policy(envelope, ...)` → `PolicyVerificationResult`; validates the canonical five-field schema (`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`) with envelope decoding and ML-DSA-65 signature verification over domain-separated bytes (`b"QERIS-POLICY-v1\x00"`).
- `qeris.device_auth`: `Ed25519DeviceCredential`, `GatewayChallengeManager`, `build_canonical_device_auth_message`, and `verify_device_signature` for long-term device authentication.
- `qeris.device_simulator`: `simulate_device_round_trip` supporting `PQC` (ML-KEM-512) and `CLASSICAL` (X25519) profiles, synthetic compute delay/timeout simulation, and S1 failure hooks.

## Key handling and wire behavior

- Do not log private keys, shared secrets, session keys, plaintext, or authentication tokens.
- The message layer currently enforces strictly increasing counters and rejects out-of-order messages.
- **AES-GCM reboot safety:** The 96-bit counter is in-memory only and resets upon restart. To avoid nonce reuse, a fresh session key must be established via handshake after every reboot. Do not reset a nonce counter while reusing its AES-GCM key. If both directions encrypt, use direction-separated keys.
- The current message envelope limit is 1 MiB; transport/fragmentation constraints may require a lower limit.
- **Hybrid mode:** The local simulator now exposes `DeviceProfile.HYBRID` using X25519MLKEM768 (X25519 + ML-KEM-768) and the RFC 9958 concatenated hybrid key-agreement approach with RFC 10024 component-share ordering. This is not a TLS 1.3 / DTLS 1.3 transport implementation; see `S1_HYBRID_PROFILE.md`.
- **Hardware validation status:** ESP32 hardware measurements, E1 wire fragmentation data, and G2 calibration data remain unverified pending physical hardware testing; no hardware evidence files are stored in `docs/evidence/`.
