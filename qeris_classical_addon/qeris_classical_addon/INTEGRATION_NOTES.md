# Antigravity handoff notes

Please integrate this add-on into the existing QERIS repository without rewriting the PQC path.

- Copy `qeris_classical/` into the repository's importable Python package area (or retain it as a top-level package and ensure the project root is on `sys.path`).
- Add `cryptography>=43.0.0` to the applicable dependency file if it is not already present. The existing S1 requirements already declare it.
- In S2, dispatch `CLASSICAL` to `qeris_classical.adapter.establish_session` only after policy signature verification, device checks, and the S3 security-floor hook return ALLOW.
- Leave the current `PQC`/`PQ` dispatch unchanged.
- Continue to reject `HYBRID`; this add-on does not implement hybrid key exchange.
- Do not let CLASSICAL satisfy a policy floor of HYBRID or PQC.
- Preserve S3 downgrade and replay/rollback controls. The message-layer replay counter in this add-on is separate from S3's policy/flow replay protection.
- Update gateway logs to report the actual executed mode and key exchange (`CLASSICAL`, `X25519`) without logging keys, shared secrets, session keys, plaintext, or ciphertext payloads.
- Add a gateway integration test that demonstrates: LOW/CLASSICAL allowed by policy can execute; a PQC minimum floor rejects CLASSICAL before encryption; HYBRID remains unsupported; the PQC path still passes.
- Do not claim that policies are classically signed. Existing policy signatures remain ML-DSA-65 unless a separate Ed25519 policy-signature change is designed and reviewed.

The standalone tests validate the add-on's local cryptographic behavior, not gateway integration or production network security.
