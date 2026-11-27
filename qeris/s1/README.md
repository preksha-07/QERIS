# QERIS — S1 cryptographic prototype

This repository contains the S1 cryptographic building blocks and a local in-process simulator. It is **not yet the integrated gateway Demo 1**.

## Scope currently implemented

- ML-DSA-65 envelope signing and verification of the canonical five-field policy schema (`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`) with domain separation `b"QERIS-POLICY-v1\x00"` (`qeris/policy/`).
- ML-KEM-512 encapsulation/decapsulation and HKDF-SHA256 session-key derivation (`qeris/session_crypto.py`).
- AES-256-GCM message protection with authenticated context and monotonic counter replay/out-of-order rejection (`qeris/secure_message.py`).
- Long-term Ed25519 device authentication with canonical handshake binding and gateway freshness challenge replay protection (`qeris/device_auth.py`).
- Local device simulator supporting `PQC` (ML-KEM-512) and `CLASSICAL` (X25519) profiles, synthetic compute delay/timeout simulation, and S1 failure hooks (`qeris/device_simulator.py`).
- Offline policy authority CLI for ML-DSA-65 key generation and envelope signing (`qeris/policy/offline_signer.py`).

## Important limitations

- **Policy storage:** S1 verifies policy signatures and structure; persistent anti-rollback storage and gateway integration belong to S2.
- **Device authentication:** The simulator implements device-side challenge-bound Ed25519 signing (`SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED`); gateway registry verification, revocation enforcement, and admission decisions (`ALLOW`) belong to S2.
- **AES-GCM nonce reboot safety:** The 96-bit counter is in-memory only and resets to 0 upon process restart. To prevent nonce reuse, a fresh session key must be established via handshake after every reboot or session reinitialization. Key reuse across encryptor instances or restarts is strictly forbidden.
- **Hybrid mode:** `DeviceProfile.HYBRID` uses the in-process X25519MLKEM768 profile (X25519 + ML-KEM-768) with RFC 9958 concatenated hybrid key-agreement approach with RFC 10024 component ordering. It is a simulator profile, not a TLS 1.3 / DTLS 1.3 implementation. See `docs/S1_HYBRID_PROFILE.md`.
- **Synthetic simulator delays:** Configurable compute delays and timeouts in `SimulatorConfig` are synthetic parameters for testing timeout and failure paths; they are NOT calibrated from real ESP32 hardware measurements.
- **Hardware validation status:** No ESP32 hardware measurements, E1 wire fragmentation data, or G2 calibration data are present in this repository; hardware validation remains unverified pending physical board testing. No ESP32 result should be claimed unless measured on hardware.

## Environment

The development environment uses Python 3.13.14, `liboqs-python==0.16.0.1` (native liboqs 0.16.0), and `cryptography==50.0.2`. Verified on Windows (win32). See `docs/evidence/s1_environment_versions.txt`.

## Setup & Verification (PowerShell)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest qeris\s1\tests\ -v --tb=short
```

Current test suite baseline: **90 passed, 12 subtests passed** in 0.71s (see `docs/evidence/s1_test_run_20261122.txt`).

## Run the local crypto simulation

```powershell
# PQC profile (default: ML-KEM-512)
python -c "from qeris.device_simulator import simulate_device_round_trip; print(simulate_device_round_trip())"

# Classical profile (X25519)
python -c "from qeris.device_simulator import simulate_device_round_trip, DeviceProfile; print(simulate_device_round_trip(profile=DeviceProfile.CLASSICAL))"
```

This is a local crypto round-trip demonstration only. It is not the gateway `ALLOW` demo.

## Demo 1 acceptance target

The integrated Demo 1 is complete only when S2's gateway can demonstrate a LOW flow being allowed using a valid policy and the final agreed policy schema, with the actual gateway decision and audit log captured. S1 supplies the crypto modules and contract; S2 performs the gateway integration.

## S1 device authentication and offline policy authority

- Device identity proof uses a long-term Ed25519 credential. X25519 remains the separate classical key-agreement mechanism; Ed25519 does not replace it.
- `qeris/device_auth.py` provides canonical transcript-bound authentication messages, Ed25519 signing/verification, and gateway challenge primitives. The gateway must issue a cryptographically random 32-byte challenge, bind it to the registered device, enforce expiry, and consume it once. The challenge manager is in-memory prototype state; deployments with multiple workers/restarts need shared durable or otherwise coordinated replay state.
- Policy signing uses ML-DSA-65 and the fixed policy domain-separation prefix in `qeris/policy/serialization.py`. The offline signer is `python -m qeris.policy.offline_signer` from the repository root.
- Generate an authority keypair on an offline/trusted machine and keep the `.key` file outside the repository and gateway. Only distribute the `.pub` file to the gateway trust configuration. Never commit or share authority private keys.

Example PowerShell commands from the repository root:

```powershell
# Generate a fresh authority keypair in a secure offline directory
python -m qeris.policy.offline_signer genkey --prefix D:\QERIS-Offline\authority_root

# Sign a single policy or flow-keyed policy bundle
python -m qeris.policy.offline_signer sign --input .\policy-input.json --key D:\QERIS-Offline\authority_root.key --output .\signed-policies.json --authority-id authority_root
```

The signer refuses to overwrite existing key or output files unless `--overwrite` is explicitly supplied. Protect and back up the private key securely. The CLI validates every policy against the canonical five-field schema and checks that the requested authority ID matches each policy. The gateway must verify envelopes using its separately configured trusted public key; it must never sign policies or load the private key at runtime.

**Prototype limitation:** the challenge manager shown here is process-local. The gateway integration must ensure that the challenge is validated and consumed atomically in the same trusted session flow, and that its state survives the deployment's concurrency/restart model. Do not claim production replay resistance from an isolated unit test alone.
