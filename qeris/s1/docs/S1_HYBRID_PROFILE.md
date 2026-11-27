# S1 Hybrid Profile — X25519MLKEM768

## Status

`DeviceProfile.HYBRID` is implemented for the **local in-process QERIS simulator**.

- Classical profile: X25519.
- PQC profile: ML-KEM-512.
- Hybrid profile: X25519 + ML-KEM-768 (`X25519MLKEM768`).

The existing Classical and PQC profiles are preserved. The Hybrid profile deliberately uses ML-KEM-768, as specified by the QERIS master blueprint's Hybrid/E1 profile, without changing the existing ML-KEM-512 PQC profile.

## What "hybrid" means

Hybrid key exchange runs both the classical and post-quantum key-establishment components in the same session. It is **not** a percentage split such as 75% PQC and 25% classical. The purpose is that the combined key establishment remains secure if at least one component remains secure.

RFC 9958 describes two general hybrid key-agreement patterns:

1. **Concatenated:** concatenate the component shared secrets and feed the result into the protocol's key schedule.
2. **Cascaded:** apply the KDF iteratively, feeding each stage into the next.

These are construction patterns, not weighting percentages. QERIS selects the concatenated X25519MLKEM768 construction because that is the group named in the master blueprint's Hybrid profile. The cascaded pattern is not implemented by this profile.

## Component share layout

The simulator follows the X25519MLKEM768 component ordering in RFC 10024:

| Item | Layout | Total |
|---|---|---:|
| Client share | ML-KEM-768 public key (1184 B) || X25519 public share (32 B) | 1216 B |
| Server share | ML-KEM-768 ciphertext (1088 B) || X25519 public share (32 B) | 1120 B |
| Combined shared secret | ML-KEM shared secret (32 B) || X25519 shared secret (32 B) | 64 B |

Both endpoints compute both components. The shared-secret order is **ML-KEM first, X25519 second**, as specified for `X25519MLKEM768` by RFC 10024. The X25519 implementation rejects invalid/all-zero ECDH shared secrets.

The simulator's `handshake_id` transcript hash binds:
- the complete client share (both client public values),
- the complete server share (ML-KEM ciphertext and server X25519 public value), and
- the device, flow, sensitivity and policy-version context.

`handshake_id` is a correlation/transcript identifier, not a TLS Finished value and not authentication by itself. Device authentication remains a separate operation.

## Key derivation and protocol boundary

The 64-byte combined shared secret is passed to QERIS's context-bound HKDF-SHA256 derivation to produce the simulator's AES-256-GCM session key. The HKDF info also includes the SHA-256 `handshake_id`, binding the derived key to both complete component shares and the same flow/policy context.

**Important limitation:** RFC 10024 defines `X25519MLKEM768` for TLS 1.3 and specifies how the combined secret enters the TLS 1.3 key schedule. The QERIS code here is a local in-process simulator, not a TLS 1.3 or DTLS 1.3 implementation. Its final QERIS HKDF context/label is application-specific. Therefore:
- do not claim RFC 10024 TLS/DTLS wire-protocol compliance or interoperability;
- do not describe the local orchestration as a full TLS/DTLS handshake;
- use a native TLS/DTLS implementation with the named group enabled if the demo requires a network-protocol Hybrid handshake.

This implementation does not define a weighted or custom combiner. It uses the concatenated PQ/T hybrid key-agreement approach described in RFC 9958 Section 13.1, with the X25519MLKEM768 component order from RFC 10024, followed by QERIS's application-specific simulator key derivation.

## Test expectations

The Hybrid tests should verify:
- ML-KEM-768 and X25519 key material are both generated.
- client/server share lengths are 1216 and 1120 bytes respectively.
- both peers derive the same 64-byte combined shared secret.
- both peers derive matching 32-byte session keys.
- the HKDF-derived session key is bound to the transcript hash.
- the transcript hash changes if either component share changes.
- AES-256-GCM telemetry encryption/decryption succeeds.
- the Hybrid profile is distinct from the unchanged ML-KEM-512 PQC profile.

The tests require the configured liboqs build to expose `ML-KEM-768`.

## References

- RFC 9794 — Terminology for Post-Quantum Traditional Hybrid Schemes.
- RFC 9954 — Hybrid Key Exchange in TLS 1.3 (protocol-specific hybrid framework).
- RFC 10024 — Post-Quantum Traditional Hybrid Key Agreement Mechanisms for TLS 1.3 (X25519MLKEM768 group and byte ordering).
- RFC 9958, Section 13.1 — overview of concatenated and cascaded hybrid key-agreement patterns; this QERIS profile uses the concatenated approach.
