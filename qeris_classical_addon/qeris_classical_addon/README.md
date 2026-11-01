# QERIS Classical Crypto Add-on (standalone)

This add-on provides a **classical session-cryptography path only**:

1. X25519 ephemeral Diffie–Hellman key agreement.
2. HKDF-SHA256 session-key derivation, using the same salt, label, and context encoding as the existing QERIS S1 `derive_session_key` implementation.
3. AES-256-GCM payload encryption with the same `QMSG` v1 envelope header, context AAD encoding, and monotonic-counter replay check as the integrated S1 message module.

It does not edit or replace any existing QERIS files. It does not implement PQC or HYBRID mode, policy signing, gateway policy decisions, S3 checks, or network transport.

## Install and test

From this directory:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The test suite uses Python's built-in `unittest` runner. No `liboqs` dependency is required for this add-on.

## Minimal use

```python
from qeris_classical import establish_session

session = establish_session(
    device_id="ESP32_NODE_01",
    flow_id="temperature_01",
    sensitivity="LOW",
    policy_version=1,
    mode="CLASSICAL",
)

envelope = session.encrypt(b"sample telemetry")
plaintext = session.decrypt(envelope)
assert plaintext == b"sample telemetry"
```

This `establish_session` is a local two-endpoint loopback demonstration, matching the local sender/receiver style of the current QERIS adapter. It generates both endpoint keypairs internally and checks that both sides derive the same shared secret. The public keys are available as `session.device_public_key` and `session.gateway_public_key` for demonstration metadata; private keys and session keys are not exposed on the session object.

## Security and integration boundaries

- X25519 key agreement alone does **not authenticate the peer**. A real network deployment must authenticate/bind the exchanged public keys to device identities (for example, through the project's authenticated device-registration mechanism) and protect against man-in-the-middle attacks.
- This sample creates a fresh ephemeral keypair for each local session. Do not persist or reuse ephemeral private keys.
- The included message channel is one-way per session key, just like the current S1 adapter's loopback use. For bidirectional traffic, derive separate direction-specific keys and use independent nonce counters; do not instantiate two encryptors with the same AES-GCM key and counter sequence.
- The policy authority signature remains ML-DSA-65 in the integrated project unless separately changed. Thus a demo using this add-on is accurately described as **CLASSICAL session key establishment and payload encryption with the existing PQC policy-signature layer**—not an entirely classical system.
- The integrated gateway currently rejects CLASSICAL at its crypto adapter. Antigravity must wire this module into S2's mode dispatch while preserving policy verification, S3 security-floor enforcement, downgrade rejection, and explicit rejection of HYBRID.
- A policy with `minimum_mode="PQC"` must never be fulfilled with this CLASSICAL session. The existing gateway/S3 allow/deny decision must happen before this adapter is called.

## Integration surface

Import:

```python
from qeris_classical.adapter import establish_session
```

Call only after the verified policy and S3 hook have allowed CLASSICAL. The function signature is intentionally close to the existing S2 adapter:

`establish_session(device_id, flow_id, sensitivity, policy_version, mode="CLASSICAL")`

The returned `ClassicalCryptoSession` has `encrypt(bytes)`, `decrypt(bytes)`, and the context fields `device_id`, `flow_id`, `sensitivity`, `policy_version`, and `mode`. It additionally exposes `key_exchange`, `device_public_key`, and `gateway_public_key`. Unlike the PQC adapter, it has no `kem_ciphertext` field.

No changes to the original S1–S4 source tree are included in this archive.
