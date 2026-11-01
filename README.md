# QERIS: Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway

[![Tests](https://img.shields.io/badge/tests-256%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Cryptography](https://img.shields.io/badge/crypto-ML--KEM--512%20%7C%20ML--DSA--65%20%7C%20X25519-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

QERIS is a modular, sensitivity-aware post-quantum migration gateway for IoT and telemetry systems. It balances security requirements against embedded physical constraints through failure-classified recovery, strict security floor enforcement, and context-bound cryptographic session encryption across both Post-Quantum (`ML-KEM-512`) and Classical (`X25519`) modes.

---

## Architecture Overview

QERIS integrates four specialized subsystems plus the classical cryptography adapter into a single coherent backend:

```text
[Client Endpoint / IoT Device]
              │
              ▼
   ┌─────────────────────┐
   │    S2 Gateway       │ ◄───► S1 Post-Quantum Cryptography (ML-DSA-65)
   │  FastAPI Controller │
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │    S3 Security      │ ◄─── Downgrade Rejector, Failure Taxonomy,
   │  & Recovery Logic   │      Replay Protection, Floor State Machine
   └──────────┬──────────┘
              │
              ├──────► [ALLOW & PQC] ───────► S1 Session Crypto (ML-KEM-512 + HKDF + AES-GCM)
              ├──────► [ALLOW & CLASSICAL] ─► Classical Crypto (X25519 + HKDF + AES-GCM)
              │
              ▼
   ┌─────────────────────┐
   │    S4 Analytics     │ ◄─── Gateway Log Bridge, Evaluation Engine,
   │  & Evaluation Suite │      Publication-Grade Statistical Metrics
   └─────────────────────┘
```

- **S1 (Cryptography & Device Engine):** ML-DSA-65 digital signatures, ML-KEM-512 key encapsulation, context-bound HKDF-SHA256 session key derivation, and AES-256-GCM authenticated message encryption.
- **Classical Crypto Add-on:** RFC 7748 X25519 key agreement with identical HKDF-SHA256 context binding and AES-256-GCM authenticated encryption.
- **S2 (Gateway & Policy Engine):** FastAPI gateway, canonical 5-field policy contract validation, device capability evaluation, dual-mode crypto adapter, and security floor enforcement.
- **S3 (Security & Recovery Logic):** 4-class failure taxonomy, monotonic replay protection with fast-forward bounds, downgrade rejection, and bounded recovery controller.
- **S4 (Data Science & Analytics):** Gateway log bridge, fault injection simulation, comparative baseline strategies, and statistical evaluation (Wilson intervals, confusion matrices).

---

## Canonical Policy Contract

All subsystems adhere to S2's canonical 5-field policy schema:

```json
{
  "flow_id": "temperature_01",
  "sensitivity": "LOW",
  "minimum_mode": "CLASSICAL",
  "policy_version": 1,
  "authority_id": "QERIS-GATEWAY"
}
```

Policies are decoupled from cryptographic signatures via `SignedPolicyEnvelope` (ML-DSA-65). Policy verification strictly precedes anti-rollback evaluation to prevent masked forgery attacks.

---

## Quickstart

### 1. Activate Environment & Run Tests
```powershell
& "..\.venv\Scripts\Activate.ps1"
python -m pytest -v
```
**Test Results:** All 256 tests (S1: 55, S3: 103, S4: 70, Classical Add-on & E2E: 28) pass with zero failures.

### 2. Launch Gateway Server
```powershell
cd qeris/s2
uvicorn gateway:app --reload
```

### 3. Verify Endpoints
- **Health Check:** `GET http://localhost:8000/health`
- **Flow Check:** `POST http://localhost:8000/check-flow`
- **Crypto Demo:** `POST http://localhost:8000/crypto-demo`

---

## Documentation

Detailed technical documentation is available in `docs/`:
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): Full architectural specification, state machines, and sequence diagrams.
- [`docs/POLICY_CONTRACT.md`](docs/POLICY_CONTRACT.md): Canonical policy schema, envelope format, and anti-rollback semantics.
- [`docs/INTEGRATION_AUDIT.md`](docs/INTEGRATION_AUDIT.md): Initial audit, dependency analysis, and schema resolution.
- [`docs/S4_INTEGRATION.md`](docs/S4_INTEGRATION.md): Shared logging contract and S4 bridge mapping.
- [`docs/BACKEND_SETUP.md`](docs/BACKEND_SETUP.md): Step-by-step installation, execution, and endpoint verification.
