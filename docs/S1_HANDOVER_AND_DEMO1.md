# QERIS S1 handover and Demo 1 readiness

Last reviewed: 2026-10-25

## 1. Demo 1 goal

Demo 1 is the gateway working-flow demonstration:

1. A device submits a LOW-sensitivity flow.
2. The gateway loads the policy.
3. The gateway verifies the policy using a trusted authority public key.
4. The gateway checks the flow's required minimum security mode and the device's registered capability.
5. The request satisfies those checks, so the gateway returns `ALLOW` and records an audit event.

S1 is responsible for the cryptographic components and their contract. S2 owns the gateway integration. The local S1 simulator is not itself proof that this end-to-end demo works.

## 2. S1 code present

| File | Current responsibility | Readiness |
|---|---|---|
| `qeris/policy/serialization.py` | Strict JSON parsing and deterministic Python JSON serialization | Provisional; not RFC 8785 JCS |
| `qeris/policy/signed_policy.py` | ML-DSA-65 signing/verification and structural validation | Useful standalone prototype; schema not aligned with S2 yet |
| `qeris/session_crypto.py` | ML-KEM-512 and HKDF-SHA256 | Local primitive path; peer authentication not included |
| `qeris/secure_message.py` | AES-256-GCM envelope, AAD context binding, strict counter replay check | Local message protection; not a transport protocol |
| `qeris/device_simulator.py` | In-process KEM → KDF → AEAD round trip | Crypto simulation only; no policy authorization decision |

## 3. Policy schema is the main integration dependency

The current S1 policy validator requires these provisional fields:

`version`, `sig_alg`, `flow_to_tier`, `tier_to_suite`, `expiry`, `revocation_list`.

S2's currently reported policy representation has these agreed fields:

`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`.

These are not equivalent schemas. Do not silently rename fields or change the production validator without agreeing on the exact signed bytes and envelope.

### Required contract decisions before gateway integration

1. **Signed object:** Is the signature over one policy record, a complete policy document, or an envelope containing the policy record?
2. **Signature metadata:** Where is the signature algorithm identifier stored? It must be unambiguous and allowlisted. The signature must cover the policy version and all authorization-relevant fields.
3. **Canonical bytes:** Current S1 serialization uses sorted JSON keys, compact separators and UTF-8, but is not RFC 8785 JCS. Decide whether to require these exact bytes or adopt a reviewed canonicalization standard. Signing and verification must use the same rule.
4. **Authority lookup:** The gateway must map `authority_id` to a preconfigured trusted public key. Never trust a public key supplied by the policy itself.
5. **Version handling:** Lower version rejects. Same version may be idempotently accepted only if the authenticated content matches the already accepted policy; different content with the same version rejects. Higher versions require successful signature and policy validation before persistent version state advances.
6. **Expiry/revocation:** Current S1 candidate fields are not enforced. Decide whether these fields are part of the final schema and define time/revocation semantics before claiming enforcement.
7. **Storage:** S2 owns persistent highest-accepted-version storage. S1 must not add a competing persistence mechanism.

## 4. Cryptographic contracts

### ML-KEM / HKDF

- Current KEM: ML-KEM-512.
- ML-KEM establishes a shared secret; it does not encrypt telemetry and does not authenticate a peer.
- HKDF-SHA256 derives a 32-byte key using length-prefixed context: device ID, flow ID, sensitivity tier and policy version.
- Context binding is not authorization. Values must be taken from trusted gateway policy/session state, not blindly trusted from a device.
- Do not log private keys, KEM shared secrets, session keys or plaintext.
- Before a production claim, define peer/device authentication, session lifecycle, key expiration, direction separation and rekey thresholds.

### AES-GCM message protection

- Current AEAD: AES-256-GCM with a 32-byte session key.
- Context is authenticated as associated data: device ID, flow ID, sensitivity tier and policy version.
- The nonce is a 96-bit monotonically increasing counter. A key must never be reused with a reset counter or a second independent encryptor.
- Receiver rejects repeated and out-of-order counters. This is a deliberate prototype behavior; a lossy transport may require a separately designed bounded replay window.
- Current defensive maximum envelope size: 1 MiB. S2/S4 must reconcile this with the transport MTU/fragmentation and resource budget before integration.
- Use fresh session keys and distinct directional keys if both sides encrypt in their own direction. Do not reuse a key/nonce pair.

## 5. Simulator limitations

`qeris/device_simulator.py` currently:

- uses a test-only local flow-to-tier map;
- uses a test-only default policy version;
- performs KEM encapsulation/decapsulation, KDF, encryption and decryption in one process;
- reports `authorization_decision=NOT_PERFORMED`;
- reports `device_authentication_status=NOT_IMPLEMENTED`.

Those are explicit limitations, not completed functionality. The simulator is useful for Demo 3's cryptographic sub-demonstration, but it must not be presented as the integrated Demo 1 `ALLOW` result.

## 6. Test and evidence checklist

### Local S1 crypto checks

- [ ] ML-KEM keypair/encaps/decaps: device and receiver shared-secret fingerprints match.
- [ ] HKDF: same context produces matching keys; a changed context produces a different derived key.
- [ ] ML-DSA: valid signature verifies; modified policy/signature fails.
- [ ] Message protection: round trip succeeds; tampering, wrong context, replay and malformed/oversized envelope reject.
- [ ] No logs contain secrets or plaintext.
- [ ] Save exact Python, wrapper and native liboqs versions plus full test output.

### S2 integrated Demo 1 evidence

- [ ] Gateway loads the agreed policy document.
- [ ] Policy signature is checked against the configured trusted authority key.
- [ ] Persistent version state is checked and updated safely.
- [ ] LOW flow resolves to the policy's LOW sensitivity/minimum mode.
- [ ] Registered device capability satisfies the minimum mode.
- [ ] Gateway returns `ALLOW` for the valid request.
- [ ] Audit log records flow/device, policy version, decision and reason without secrets.
- [ ] Invalid signature and stale/rollback policy are rejected in negative tests.

## 7. Ownership boundaries

- **S1:** crypto APIs, tests, key handling notes, crypto measurements, simulator and this interface documentation.
- **S2:** policy schema implementation in gateway, trusted authority lookup, persistent version store, device capability registry, gateway decision and audit logging, integration demo.
- **S3:** threat model, security-floor invariant monitor, downgrade/replay tests, failure taxonomy and recovery controller.
- **S4:** log parser, experiment runner, fault injection, statistics and result plots.

## 8. Known next actions for S1

1. Keep the current 33-test policy baseline and current crypto tests as a regression baseline.
2. Agree the signed policy representation with S2 before altering the six-field validator.
3. Keep the simulator honest about authorization/authentication not being implemented until an authenticated contract exists.
4. Use the crypto tests as Demo 3 evidence, separate from the S2 gateway `ALLOW` evidence.
5. Re-run all tests on the actual Windows development machine after copying these files, because native liboqs availability is environment-dependent.

## 9. Cross-account continuation brief

Project: QERIS, “Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway.” User is S1 (Cryptography + Device Engineer). The user's immediate target is **Demo 1**, not the full final project. Demo 1's integrated gateway path is owned by S2; S1 should make the pre-integration crypto modules, tests and docs ready. Do not push to GitHub until Demo 1 is complete. Preserve all work; no commits or pushes unless explicitly requested.

Demo 1: LOW flow → gateway reads policy → policy valid → required security mode satisfied → `ALLOW`. Demo 2: CRITICAL flow with minimum HYBRID, request CLASSICAL → reject at security-floor check and log reason. Demo 3: separately show ML-KEM shared-secret agreement and ML-DSA valid-signature success / modified-signature failure.

Current S1 code has ML-DSA-65 signed policy prototype, ML-KEM-512 + HKDF-SHA256, AES-256-GCM envelope and in-process crypto simulator. Current policy schema is provisional six fields (`version`, `sig_alg`, `flow_to_tier`, `tier_to_suite`, `expiry`, `revocation_list`) and does not match S2's reported five-field schema (`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`). Do not silently rewrite the schema. First agree exact signed object/envelope, signature algorithm metadata, canonical bytes and version semantics. S2 owns persistent anti-rollback storage and gateway integration. The simulator currently does not perform authorization or device authentication.

Previously, the user's Windows environment reported Python 3.13.14, `liboqs-python==0.16.0.1`, native liboqs 0.16.0, and 33 tests passing (6 crypto smoke + 27 signed-policy tests). In the review environment, only the nine AES-GCM message tests were runnable and passed; full ML-KEM/ML-DSA suite was not independently reproduced because `oqs` was unavailable there. A 1 MiB max envelope guard and corresponding test were added in this reviewed source package; verify all tests on the Windows development machine before adopting.
