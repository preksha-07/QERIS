# QERIS S2: Gateway and Cloud Operational Guide

This guide describes operational workflows, configuration options, administrative tasks, and troubleshooting procedures for the QERIS S2 Gateway and Cloud infrastructure.

---

## 1. Prerequisites and Environment

- **Python:** 3.10+ (Tested on Python 3.14.0 Windows x86_64 and Linux).
- **Core Dependencies:**
  - `cryptography>=50.0.0` (Native NIST FIPS 204 ML-DSA-65 and FIPS 203 ML-KEM).
  - `fastapi>=0.110.0`
  - `uvicorn>=0.28.0`
  - `httpx>=0.27.0`
  - `pydantic>=2.6.0`
  - `pytest>=8.0.0`
  - `pyyaml>=6.0.0`

### Virtual Environment Setup
```powershell
# Windows
uv venv .venv
.\.venv\Scripts\activate
uv pip install fastapi uvicorn cryptography pyyaml httpx pydantic pytest
```

---

## 2. Service Startup

### 2.1 Starting the Cloud Service
The cloud telemetry service provides persistent ingestion, query endpoints, and database segregation:

```powershell
# Starts on http://127.0.0.1:8001
.\.venv\Scripts\python.exe -m uvicorn qeris.s2.cloud_service:app --host 127.0.0.1 --port 8001
```

Health check:
```powershell
curl http://127.0.0.1:8001/api/v1/cloud/health
```

### 2.2 Starting the Security Gateway
The gateway initializes authority keys, loads registered devices from `qeris/s2/devices.json`, and installs initial signed policy from `qeris/s2/policy.json`:

```powershell
# Starts on http://127.0.0.1:8000
.\.venv\Scripts\python.exe qeris/s2/gateway.py
```

Health check:
```powershell
curl http://127.0.0.1:8000/health
```

---

## 3. Administrative Workflows

### 3.1 Authority Keypair Generation (Offline)
In accordance with Trust Boundary 3 (TB3), authority keypairs are generated and held strictly offline:

```python
from qeris.s2.crypto_engine import generate_authority_keypair

priv_pem, pub_pem, pub_hex = generate_authority_keypair()
with open("authority_priv.pem", "wb") as f:
    f.write(priv_pem)
with open("authority_pub.pem", "wb") as f:
    f.write(pub_pem)
```

### 3.2 Authoring and Signing Policies Offline
Policies are defined using `PolicyDocumentModel` and signed via `sign_policy_document` using NIST FIPS 204 ML-DSA-65:

```python
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document

doc = PolicyDocumentModel(
    authority_id="QERIS-GATEWAY",
    policy_version=2,
    policies={
        "telemetry_stream": FlowPolicyModel(
            flow_id="telemetry_stream",
            device_scope=["dev_001", "dev_002"],
            sensitivity="MEDIUM",
            minimum_mode="HYBRID",
            approved_security_profiles=[
                "HYBRID_X25519_MLKEM_AESGCM",
                "PQC_MLKEM512_AESGCM",
            ],
        ),
        "emergency_actuation": FlowPolicyModel(
            flow_id="emergency_actuation",
            device_scope=["dev_002"],
            sensitivity="CRITICAL",
            minimum_mode="PQC",
            approved_security_profiles=["PQC_MLKEM768_AESGCM"],
        ),
    },
)

with open("authority_priv.pem", "rb") as f:
    priv_pem = f.read()

signed_envelope = sign_policy_document(doc, priv_pem)
envelope_json = signed_envelope.model_dump_json(indent=2)
with open("new_policy.json", "w") as f:
    f.write(envelope_json)
```

### 3.3 Installing Signed Policy on Gateway
Submit the signed envelope to the gateway administration endpoint:

```powershell
curl -X POST http://127.0.0.1:8000/api/v1/admin/policy `
  -H "Content-Type: application/json" `
  -d @new_policy.json
```

**Anti-Rollback Guarantee:**
- If incoming `policy_version <= active_policy_version`, the gateway rejects the request with HTTP 409 Conflict.
- An exact duplicate policy (matching version and SHA-256 digest) is accepted idempotently without incrementing state.
- In-memory activation takes place **strictly after** the SQLite transaction commits to disk (`policy_store.db`).

### 3.4 Registering IoT Devices
Devices must be registered in the gateway capability registry before sessions can be established:

```powershell
curl -X POST http://127.0.0.1:8000/api/v1/admin/devices `
  -H "Content-Type: application/json" `
  -d '{
    "device_id": "esp32_sensor_42",
    "device_class": "esp32_constrained",
    "supported_modes": ["CLASSICAL", "HYBRID"],
    "supported_security_profiles": ["CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM"],
    "ram_bytes_available": 327680,
    "max_packet_size_mtu": 1500
  }'
```

---

## 4. Verification and Simulation Tools

### 4.1 Running the Device Simulator
Simulates benign and malicious edge devices attempting valid flows, illegal downgrades, sensitivity overrides, and floods:

```powershell
# Executes full test harness (auto-detects live server or runs in-process)
.\.venv\Scripts\python.exe qeris/s2/device_simulator.py
```

Expected output:
- `case1_low_classical_allowed`: **PASS**
- `case2_critical_pqc_allowed`: **PASS**
- `case3_critical_downgrade_rejected`: **PASS (Downgrade Blocked)**
- `case4_device_label_override_rejected`: **PASS (Device Claim Ignored)**
- `case5_unregistered_device_rejected`: **PASS (Unregistered Rejected)**
- `case6_telemetry_forwarded`: **PASS (Queued/Delivered)**

### 4.2 Replaying Experimental Datasets
Streams historical pilot runs from `data/raw/` through the S2 Gateway pipeline:

```powershell
.\.venv\Scripts\python.exe qeris/s2/data_replay.py
```

### 4.3 Generating Structured Evidence
Executes end-to-end security scenarios and updates JSON evidence files in `qeris/s2/evidence/`:

```powershell
.\.venv\Scripts\python.exe qeris/s2/generate_evidence.py
```

Output files:
1. `policy_anti_rollback_evidence.json`: Proof of monotonic version enforcement, replay defense, and restart persistence.
2. `security_floor_enforcement_evidence.json`: Proof of downgrade blocking, sensitivity derivation, and S3 integration.
3. `cloud_pipeline_and_outage_evidence.json`: Proof of telemetry forwarding, FIFO outage queue buffering, and drain recovery.
4. `dataset_replay_evidence.json`: Audit log and metrics from replaying `pilot_smoke` dataset.

### 4.4 Running Repository Test Suites
Execute all 248 unit and integration tests across modules S1, S2, S3, and S4:

```powershell
.\.venv\Scripts\pytest.exe -v
```

---

## 5. Docker Deployment

### 5.1 Dockerfile Structure
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn cryptography pyyaml httpx pydantic pytest

COPY qeris/ /app/qeris/
COPY data/ /app/data/

ENV PYTHONPATH=/app
EXPOSE 8000 8001

CMD ["python", "qeris/s2/gateway.py"]
```

### 5.2 Compose Configuration (`docker-compose.yml`)
```yaml
version: '3.8'

services:
  qeris-cloud:
    build: .
    command: python -m uvicorn qeris.s2.cloud_service:app --host 0.0.0.0 --port 8001
    ports:
      - "8001:8001"
    volumes:
      - cloud-data:/app/qeris/s2

  qeris-gateway:
    build: .
    command: python qeris/s2/gateway.py
    ports:
      - "8000:8000"
    environment:
      - QERIS_CLOUD_URL=http://qeris-cloud:8001
    depends_on:
      - qeris-cloud
    volumes:
      - gateway-data:/app/qeris/s2

volumes:
  cloud-data:
  gateway-data:
```

---

## 6. Troubleshooting and Operational Invariants

| Issue | Cause | Resolution |
|---|---|---|
| **HTTP 409 Conflict on Policy Update** | Attempted to install policy version <= highest accepted version | Ensure new policy document increments `policy_version`. Verify `policy_store.db` latest version. |
| **HTTP 403 Floor Unreachable** | Device lacks RAM or MTU for required PQC profile | Check device capability registration. If device is constrained (e.g. 8KB RAM), it cannot participate in CRITICAL flows. |
| **HTTP 429 Too Many Requests** | Device exceeded burst capacity (10 tokens, refill 2.0/s) | Wait 1-2 seconds for token bucket refill. Legitimate devices should implement backoff. |
| **DEC-4 STALE Session Invalidation** | Active session was negotiated under previous policy epoch and profile is no longer permitted | Re-negotiate session via `POST /api/v1/handshake/initiate`. |
| **SQLite File Lock on Windows (`WinError 32`)** | Multiple processes accessing SQLite DB simultaneously | SQLite is configured in WAL mode. Ensure connections use context managers with explicit close. |
| **Cloud Outage Queue Full** | Prolonged cloud outage exceeded bounded buffer (1000 records) | Inspect cloud service health. Backpressure is deliberately applied to protect gateway memory. |
