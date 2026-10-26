# QERIS — S1 cryptographic prototype

This repository contains the S1 cryptographic building blocks and a local in-process simulator. It is **not yet the integrated gateway Demo 1**.

## Scope currently implemented

- ML-DSA-65 signing and verification of a **provisional** policy schema (`qeris/policy/`).
- ML-KEM-512 encapsulation/decapsulation and HKDF-SHA256 session-key derivation (`qeris/session_crypto.py`).
- AES-256-GCM message protection with authenticated context and replay/out-of-order rejection (`qeris/secure_message.py`).
- A local simulator that joins KEM, KDF and AEAD operations (`qeris/device_simulator.py`).

## Important limitations

- The policy module's six-field schema is provisional and is not the same as S2's current five-field policy representation (`flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `authority_id`). Do not connect these schemas until the signed representation/envelope is agreed in `docs/S1_HANDOVER_AND_DEMO1.md`.
- The simulator uses a test-only local flow map. It does not read a signed policy from S2's gateway, make an `ALLOW` decision, or implement device authentication.
- `last_seen_version` checking in the policy verifier is caller-supplied/in-memory only. Persistent anti-rollback storage belongs to S2.
- Matching KEM shared secrets do not authenticate either peer.
- The current AES-GCM message module uses a strict increasing counter, so out-of-order messages are rejected. Its 1 MiB envelope limit is a defensive prototype limit and must be reconciled with the selected transport/fragmentation budget.
- No ESP32 result should be claimed unless it has actually been measured on the board.

## Environment

The previously reported Windows development environment used Python 3.13.14, `liboqs-python==0.16.0.1` (wrapper), native liboqs 0.16.0, and `cryptography`. Native liboqs availability depends on the host setup. See `requirements.txt`; validate exact versions on the machine used for the demo.

## Setup (PowerShell)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

If `liboqs-python` cannot load a native liboqs library on your machine, resolve that installation separately; a successful `pip install` alone does not prove the native backend is usable.

## Run the local crypto simulation

```powershell
python -c "from qeris.device_simulator import simulate_device_round_trip; print(simulate_device_round_trip())"
```

This is a local crypto round-trip demonstration only. It is not the gateway `ALLOW` demo.

## Demo 1 acceptance target

The integrated Demo 1 is complete only when S2's gateway can demonstrate a LOW flow being allowed using a valid policy and the final agreed policy schema, with the actual gateway decision and audit log captured. S1 supplies the crypto modules and contract; S2 performs the gateway integration.
