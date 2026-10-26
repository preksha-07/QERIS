# S1 → S2 gateway interface proposal (for confirmation)

Status: **proposal, not an approved schema**. S2 owns gateway integration. This document intentionally does not redefine S2's policy JSON.

## Required inputs to S1 crypto/session path

- `device_id`: registry-resolved identity string; authentication/registry decision is made by gateway.
- `flow_id`: requested flow identifier; sensitivity and minimum mode come from the verified gateway policy, not from a device-supplied tier.
- `sensitivity`: gateway-resolved policy value.
- `policy_version`: version of the verified policy used to authorize this session.
- `session_key`: 32-byte key derived by the approved session-establishment path; must not be logged.

## Policy verification boundary

Before a policy is used to authorize a request, the gateway must:

1. Parse the agreed policy/envelope strictly.
2. Resolve `authority_id` through a trusted configured key mapping.
3. Verify the signature over the exact agreed signed bytes with an allowlisted ML-DSA algorithm.
4. Validate policy fields and allowed values.
5. Check persistent version/replay state owned by S2.
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
- `qeris.secure_message.MessageEncryptor(key, MessageContext(...)).encrypt(plaintext)` → authenticated envelope bytes.
- `qeris.secure_message.MessageDecryptor(key, same_context).decrypt(envelope)` → plaintext bytes or a typed exception.
- `qeris.policy.verify_policy(...)` → `PolicyVerificationResult`; currently validates the provisional six-field schema and must not be treated as compatible with S2 until schema/envelope agreement.

## Key handling and wire behavior

- Do not log private keys, shared secrets, session keys, plaintext, or authentication tokens.
- The message layer currently enforces strictly increasing counters and rejects out-of-order messages.
- Do not reset a nonce counter while reusing its AES-GCM key. If both directions encrypt, use direction-separated keys or an explicitly safe nonce allocation design.
- The current message envelope limit is 1 MiB; transport/fragmentation constraints may require a lower limit.
- No custom hybrid combiner is defined by S1. Hybrid negotiation must use a reviewed construction agreed by the team.
