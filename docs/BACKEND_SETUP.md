# QERIS Backend Setup and Execution Guide

**Target System:** QERIS Sensitivity-Aware Post-Quantum Migration Gateway  
**Environment:** Python 3.10+ (Tested with Python 3.13)  
**Dependencies:** `liboqs-python`, `cryptography`, `fastapi`, `uvicorn`, `pytest`, `pydantic`

---

## 1. Prerequisites and Installation

### 1.1 Python Virtual Environment
Activate the project's virtual environment:

**Windows PowerShell:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
& "..\.venv\Scripts\Activate.ps1"
```

**Linux / macOS:**
```bash
source ../.venv/bin/activate
```

### 1.2 Core Libraries
Ensure the cryptographic and gateway dependencies are installed:
```bash
pip install liboqs-python cryptography fastapi uvicorn pytest pydantic
```

---

## 2. Directory Layout

```text
QERIS/
├── conftest.py                     # Root test harness configuration
├── docs/                           # Architecture, audit, contract specifications
│   ├── ARCHITECTURE.md             # Complete system architecture specification
│   ├── INTEGRATION_AUDIT.md        # Initial baseline inspection & audit report
│   ├── POLICY_CONTRACT.md          # Canonical 5-field policy contract specification
│   ├── S4_INTEGRATION.md           # S4 shared logging bridge specification
│   └── BACKEND_SETUP.md            # This setup and execution guide
├── qeris/                          # Core codebase
│   ├── __init__.py                 # Namespace extender for unified package discovery
│   ├── s1/                         # S1 Cryptography & Device Engine
│   │   ├── qeris/
│   │   │   ├── policy/             # ML-DSA-65 signing, canonical serialization
│   │   │   ├── session_crypto.py   # ML-KEM-512 and HKDF-SHA256 key agreement
│   │   │   └── secure_message.py   # AES-256-GCM context-bound encryption
│   │   └── tests/                  # S1 unit tests (55 tests)
│   ├── s2/                         # S2 Gateway & Policy Management
│   │   ├── gateway.py              # FastAPI integrated gateway server
│   │   ├── policy_manager.py       # S1+S3 signed policy lifecycle manager
│   │   ├── crypto_adapter.py       # ML-KEM + AES-GCM session adapter
│   │   ├── policy.json             # Canonical source policies
│   │   ├── signed_policies.json    # ML-DSA-65 signed policy envelopes
│   │   ├── devices.json            # Device capability registry
│   │   └── gateway_logs.jsonl      # Operational audit logs
│   ├── s3/                         # S3 Security & Recovery Logic
│   │   ├── s3_gateway_hook.py      # S2-S3 integration adapter
│   │   ├── failure_taxonomy.py     # Signal-to-cause classification
│   │   ├── downgrade_rejection.py  # Security floor enforcement
│   │   ├── replay_protection.py    # Persistent monotonic version store
│   │   ├── recovery_controller.py  # Bounded recovery and backoff
│   │   └── floor_state_machine.py  # Flow state transitions
│   └── s4/                         # S4 Data Science & Evaluation
│       ├── gateway_log_bridge.py   # Runtime log to S4 LogRecord converter
│       ├── test_gateway_log_bridge.py # Bridge test suite (26 tests)
│       ├── log_schema.py           # Canonical S4 schema
│       ├── log_parser.py           # Ingestion and querying engine
│       ├── baseline_engine.py      # 7 comparative baseline strategies
│       └── analysis.py             # Statistical confidence intervals & metrics
└── tests/                          # End-to-end integration test suite
    └── test_backend_integration.py # 11 cross-module E2E tests
```

---

## 3. Running Test Suites

Execute all test suites from the repository root:

```bash
# Run the entire repository test suite (256 tests total)
python -m pytest -v

# Run individual subsystem suites
python -m pytest qeris/s1/ -v
python -m pytest qeris/s3/ -v
python -m pytest qeris/s4/ -v
python -m pytest qeris_classical_addon/ -v
python -m pytest tests/test_backend_integration.py -v
```

---

## 4. Running the Gateway Server

To start the integrated QERIS gateway:

```bash
cd qeris/s2
uvicorn gateway:app --host 0.0.0.0 --port 8000 --reload
```

---

## 5. API Verification and Endpoints

### 5.1 System Health
```bash
curl -s http://localhost:8000/health | jq .
```
**Response:**
```json
{
  "status": "HEALTHY",
  "verified_flows": ["emergency_stop", "telemetry_secure", "temperature_01"],
  "authority_id": "QERIS-GATEWAY",
  "persisted_policy_version": 1,
  "registered_devices": ["device_001", "device_002", "device_003"]
}
```

### 5.2 Flow Authorization Check (`POST /check-flow`)
Test an allowed PQC transmission:
```bash
curl -X POST http://localhost:8000/check-flow \
  -H "Content-Type: application/json" \
  -d '{"device_id": "device_002", "flow_id": "temperature_01", "requested_mode": "PQC"}'
```
**Response:**
```json
{
  "trace_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "flow_id": "temperature_01",
  "sensitivity": "LOW",
  "minimum_mode": "CLASSICAL",
  "requested_mode": "PQC",
  "decision": "ALLOW",
  "reason": "Policy and device capability satisfied",
  "s3_verdict": "NONE",
  "cause_label": "none"
}
```

### 5.3 Downgrade Rejection Check
Attempt to negotiate CLASSICAL on a flow requiring PQC:
```bash
curl -X POST http://localhost:8000/check-flow \
  -H "Content-Type: application/json" \
  -d '{"device_id": "device_002", "flow_id": "telemetry_secure", "requested_mode": "CLASSICAL"}'
```
**Response:**
```json
{
  "decision": "REJECT",
  "reason": "mode_below_floor",
  "s3_verdict": "DISCARD_AND_LOG",
  "cause_label": "security_failure"
}
```

### 5.4 Classical Cryptographic Roundtrip (`POST /crypto-demo`)
```bash
curl -X POST http://localhost:8000/crypto-demo \
  -H "Content-Type: application/json" \
  -d '{"device_id": "device_001", "flow_id": "temperature_01", "message": "Telemetry: 21.0 C", "requested_mode": "CLASSICAL"}'
```
**Response:**
```json
{
  "decision": "ALLOW",
  "crypto_suite": "X25519 + HKDF-SHA256 + AES-256-GCM",
  "decrypted_message": "Telemetry: 21.0 C",
  "crypto_status": "VERIFIED_ROUNDTRIP"
}
```

### 5.5 Post-Quantum Cryptographic Roundtrip (`POST /crypto-demo`)
```bash
curl -X POST http://localhost:8000/crypto-demo \
  -H "Content-Type: application/json" \
  -d '{"device_id": "device_002", "flow_id": "telemetry_secure", "message": "Telemetry: 24.5 C", "requested_mode": "PQC"}'
```
**Response:**
```json
{
  "decision": "ALLOW",
  "crypto_suite": "ML-KEM-512 + HKDF-SHA256 + AES-256-GCM",
  "decrypted_message": "Telemetry: 24.5 C",
  "crypto_status": "VERIFIED_ROUNDTRIP"
}
```

---

## 6. S4 Ingestion and Evaluation

To ingest runtime audit logs and compute statistical summaries:

```python
from qeris.s4.gateway_log_bridge import GatewayLogBridge
from qeris.s4.analysis import StatisticalAnalyzer

bridge = GatewayLogBridge()
table = bridge.ingest_file("qeris/s2/gateway_logs.jsonl")

matrix = StatisticalAnalyzer.evaluate_classifier(table)
print("Classification Accuracy:", matrix.accuracy)
```
