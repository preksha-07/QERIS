# S1 Device Authentication and Offline Policy Signing

## Device authentication (Ed25519)

S1 uses a long-term Ed25519 credential for device proof of possession. The raw public key is 32 bytes and the signature is 64 bytes. The private key stays with the device; `Ed25519DeviceCredential` intentionally redacts it from `repr` and `str`. X25519 remains the classical session key-agreement primitive and is not replaced by Ed25519. ML-KEM-512 remains the PQ key-establishment primitive.

The canonical authentication message uses length-prefixed fields to avoid concatenation ambiguity:

1. 32-bit big-endian length + `DEVICE_AUTH_DOMAIN_SEPARATOR` (`b"QERIS-DEVICE-AUTH-v1\x00"`, 21 bytes);
2. length + UTF-8 device ID;
3. length + 64-character lowercase SHA-256 `handshake_id`;
4. length + 32-byte gateway challenge;
5. unsigned 64-bit big-endian Unix timestamp.

The device signs the complete canonical message with Ed25519. The gateway verifies using the public key enrolled for that device. The `handshake_id` is only a transcript correlation value; it is not authentication by itself.

`GatewayChallengeManager` creates random 32-byte challenges, binds them to a device ID, applies a TTL, and rejects reuse. It is an in-memory S1 reference primitive. A production gateway must ensure signature verification and challenge consumption are performed in the same trusted request flow, atomically, and with challenge state shared across workers/restarts. The gateway owns the registry, revocation, HTTP mapping, and integration.

## Offline ML-DSA-65 policy signing

`qeris/policy/offline_signer.py` is an offline authority CLI. It signs the canonical five-field policy using ML-DSA-65 over:

`DOMAIN_SEPARATION_LABEL || serialize_policy_to_bytes(policy)`

The label is defined in `qeris/policy/serialization.py` (`b"QERIS-POLICY-v1\x00"`). The signer validates the policy schema, validates bundle keys against each policy's `flow_id`, and optionally checks that every `authority_id` matches `--authority-id`. Signed envelopes contain the policy, `sig_alg`, and hex signature.

### Commands

Run from the repository root in the configured S1 Python environment:

```powershell
python -m qeris.policy.offline_signer genkey --prefix D:\QERIS-Offline\authority_root
python -m qeris.policy.offline_signer sign --input .\policy-input.json --key D:\QERIS-Offline\authority_root.key --output .\signed-policies.json --authority-id authority_root
```

The CLI refuses to overwrite existing files unless `--overwrite` is specified. On POSIX, generated private-key files are owner-readable/writable only. On Windows, store the key in a directory protected by an appropriate NTFS ACL or hardware-backed secret store. Keep `.key` files outside source control and outside the gateway. Distribute only the `.pub` file to the trusted gateway configuration.

### Security and operational boundaries

- Never commit, email, or include private authority keys in project repositories.
- If a private key has already been shared, treat it as compromised: generate a replacement authority keypair, update trusted public-key configuration through the approved process, and re-sign policies. Do not silently replace a key that existing deployed policies depend on.
- The gateway verifies signatures; it must not sign policies at runtime or load the authority private key.
- **Environment & Verification:** Tested with `liboqs-python==0.16.0.1` (native liboqs 0.16.0) and `cryptography==50.0.2` on Python 3.13.14. Full test suite passing at **90 passed, 12 subtests passed** (see `docs/evidence/s1_test_run_20261122.txt`).
- **Simulator Profiles:** The device simulator supports `PQC` (ML-KEM-512), `CLASSICAL` (X25519), and an in-process `HYBRID` X25519MLKEM768 profile (X25519 + ML-KEM-768). Hybrid is not a TLS/DTLS implementation. Synthetic compute delays and timeouts are for testing only and are not calibrated from hardware.
- **AES-GCM Nonce Reboot Safety:** Nonce counter is in-memory only and resets on process restart; fresh handshake session key derivation is required per restart to prevent nonce reuse.
- This CLI provides offline signing mechanics; key custody, backup, rotation approval, and distribution remain operational responsibilities.
