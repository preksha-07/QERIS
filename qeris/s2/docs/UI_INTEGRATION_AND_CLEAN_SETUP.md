# QERIS S2: UI Integration & Clean-Clone Setup Specification

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems (QERIS)  
**Authoritative Reference:** 37-page *Master Project Implementation + Research Blueprint*  
**Subsystems Involved:** S2 (Gateway, Policy Engine, Cloud Service), UI (Frontend Dashboard)  
**Date:** 2026-11-21  
**Milestone:** Phase 4 UI Integration with Frozen S2 Backend  

---

## 1. Clean-Clone Setup Guide

This guide describes how to deploy and run QERIS from a clean clone without relying on ambient developer state or committed secrets.

### 1.1 Prerequisites
- Python 3.11+ (tested with `uv` package manager)
- Node.js 18+ and `npm` 9+ (tested with Node v24.22.0, npm 11.19.1)
- Git

### 1.2 Step-by-Step Clean Deployment

#### Step 1: Clone and Configure Environment
```bash
git clone <repository_url> qeris-final
cd qeris-final

# Create local environment file from verified template
cp .env.example .env
```
Edit `.env` to configure operational credentials:
```ini
QERIS_ADMIN_API_KEY=your_secure_random_admin_api_key_here
QERIS_GATEWAY_HOST=0.0.0.0
QERIS_GATEWAY_PORT=8000
QERIS_CLOUD_URL=https://qeris-cloud:8001
QERIS_CLOUD_CA_CERT=/app/qeris/s2/certs/cloud_cert.pem

# Frontend settings
VITE_API_BASE_URL=http://localhost:8000
VITE_CLOUD_URL=https://localhost:8001
VITE_ADMIN_API_KEY=your_secure_random_admin_api_key_here
```

#### Step 2: Install Python Dependencies & Verify Cryptographic Subsystem
```bash
# Using uv (recommended)
uv venv
uv pip install -r requirements.txt
```

#### Step 3: Launch Cloud Telemetry Service (Port 8001, TLS Enabled)
On first launch, `ensure_cloud_tls_certs()` automatically generates self-signed ECDSA P-256 certificates with Subject Alternative Names (`localhost`, `qeris-cloud`, `qeris-gateway`, `127.0.0.1`):
```bash
python -m uvicorn qeris.s2.cloud_service:app --host 127.0.0.1 --port 8001 --ssl-keyfile qeris/s2/certs/cloud_key.pem --ssl-certfile qeris/s2/certs/cloud_cert.pem
```

#### Step 4: Launch Security Gateway Service (Port 8000)
On first launch, `gateway.py` automatically generates ML-DSA-65 authority keypairs if missing (`qeris/s2/.authority_keys/authority_priv.pem`), initializes SQLite WAL databases (`device_registry.db`, `policy_store.db`), and installs Version 1 signed policy:
```bash
python qeris/s2/gateway.py
```

#### Step 5: Launch Frontend UI (Port 5173)
```bash
cd ui
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. The UI connects to the gateway and displays `GATEWAY ONLINE` with live telemetry.

---

## 2. Frozen Backend Interface Contracts

All endpoints exposed by the QERIS Gateway and Cloud services are documented below with their exact authentication requirements and status codes.

| Service | Endpoint | Method | Auth Scheme | Status Code | Description |
|---|---|---|---|---|---|
| **Gateway** | `/health` | `GET` | Public (None) | `200 OK` | Gateway container and service liveness check |
| **Gateway** | `/api/v1/gateway/health` | `GET` | Public (None) | `200 OK` | Canonical healthcheck alias |
| **Gateway** | `/api/v1/gateway/status` | `GET` | Public (None) | `200 OK` | Runtime metrics: active baseline, policy version, queue size, dropped count |
| **Gateway** | `/check-flow` | `POST` | Public (None) | `200 OK` (ALLOW), `403 Forbidden` (REJECT / FLOOR_UNREACHABLE) | Authoritative policy floor & capability evaluation |
| **Gateway** | `/api/v1/handshake/initiate` | `POST` | Public (None) | `200 OK`, `403 Forbidden` | Initiates session cryptographic negotiation |
| **Gateway** | `/api/v1/handshake/complete` | `POST` | Public (None) | `200 OK`, `403 Forbidden` | Finalizes session and derives session context |
| **Gateway** | `/api/v1/telemetry` | `POST` | Public (None) | `200 OK` (ACCEPTED), `400` / `403` | Edge telemetry ingress with DEC-4 epoch check & cloud forward |
| **Gateway** | `/api/v1/admin/baseline` | `GET` | Admin Key | `200 OK`, `401 Unauthorized`, `403 Forbidden` | Returns current active baseline mode & all 7 baselines |
| **Gateway** | `/api/v1/admin/baseline` | `POST` | Admin Key | `200 OK` (UPDATED), `401`, `403`, `422` | Switches active baseline mode |
| **Gateway** | `/api/v1/admin/policy` | `GET` | Admin Key | `200 OK`, `401`, `403` | Retrieves active signed policy document & flows |
| **Gateway** | `/api/v1/admin/policy` | `POST` | Admin Key | `200 OK` (INSTALLED), `400`, `401`, `403` | Installs new ML-DSA signed policy (anti-rollback enforced) |
| **Gateway** | `/api/v1/admin/devices` | `GET` | Admin Key | `200 OK`, `401`, `403` | Lists registered device capability profiles |
| **Gateway** | `/api/v1/admin/devices` | `POST` | Admin Key | `200 OK` (REGISTERED), `401`, `403` | Registers new device capability profile |
| **Gateway** | `/api/v1/admin/audit-logs` | `GET` | Admin Key | `200 OK`, `401`, `403` | Retrieves structured gateway audit event records |
| **Gateway** | `/api/v1/admin/config` | `GET` | Admin Key | `200 OK`, `401`, `403` | Returns frozen config parameters and config digest |
| **Gateway** | `/api/v1/admin/reset` | `POST` | Admin Key | `200 OK` (RESET_COMPLETED), `401`, `403` | Wipes ephemeral experiment state (rate limiters, sessions, queue) |
| **Cloud** | `/health` | `GET` | Public (None) | `200 OK` | Cloud service health probe |
| **Cloud** | `/api/v1/cloud/health` | `GET` | Public (None) | `200 OK` | Canonical cloud health probe with total records count |
| **Cloud** | `/api/v1/cloud/stats` | `GET` | Public (None) | `200 OK` | Aggregated records by flow ID and sensitivity tier |
| **Cloud** | `/api/v1/cloud/telemetry` | `GET` | Public (None) | `200 OK` | Query filtered telemetry records stored in cloud database |
| **Cloud** | `/api/v1/cloud/reset` | `POST` | Public (None) | `200 OK` | Clears all telemetry records from cloud database |

---

## 3. Administrative Authentication Status Code Reconciliation

The gateway implements a strict fail-secure administrative security boundary across all `/api/v1/admin/*` endpoints:
1. **Unconfigured Gateway State (`HTTP 403 Forbidden`):**
   If `admin_api_key` is `None` or empty, the entire administrative API is disabled. Any incoming request to `/api/v1/admin/*` is rejected with:
   ```json
   {
     "detail": "Forbidden: Admin API access is disabled because no admin API key is configured"
   }
   ```
2. **Missing or Invalid Credential (`HTTP 401 Unauthorized`):**
   When `admin_api_key` is configured, callers must provide a matching `X-Admin-Key` or `Authorization: Bearer <key>` header. If the header is missing or incorrect, the gateway rejects the request with:
   ```json
   {
     "detail": "Unauthorized: Invalid or missing admin API key"
   }
   ```
3. **Authorized Request (`HTTP 200 OK`):**
   When a valid matching credential is provided, the administrative request is authorized and processed.

---

## 4. UI Integration Mapping

| UI Page / Component | User Action | Backend Endpoint | Live vs Sample Behavior |
|---|---|---|---|
| **App Layout** (`Sidebar.tsx`) | 15s polling | `GET /api/v1/gateway/status` | Displays real-time `ONLINE`/`OFFLINE` and active baseline badge (`full_gateway`). |
| **Dashboard** (`Dashboard.tsx`) | Initial load & polling | `GET /api/v1/gateway/status`, `GET /api/v1/admin/baseline`, `GET /api/v1/admin/audit-logs` | Renders live stats. If admin key unset, falls back to public gateway status and displays `LIVE BACKEND CONNECTED` / `OFFLINE / SAMPLE DATA`. |
| **Dashboard** (`Dashboard.tsx`) | Baseline mode switch | `POST /api/v1/admin/baseline` | Updates active baseline across B1–B7. Prompts for admin key if 401/403. |
| **Dashboard** (`Dashboard.tsx`) | Experiment state reset | `POST /api/v1/admin/reset` | Wipes sessions and cloud queue on demand. |
| **Flow Monitor** (`Flows.tsx`) | Custom flow check | `POST /check-flow` | Submits device ID, flow ID, requested mode. Renders authoritative verdict, floor, and S3 status. |
| **Flow Monitor** (`Flows.tsx`) | 4 Demo Scenarios | `POST /check-flow` | Runs scenarios against real gateway policy, showing live decision vs expected baseline. |
| **Devices** (`Devices.tsx`) | Transmission Simulator | `POST /check-flow` then `POST /api/v1/telemetry` | Submits payload, receives DEC-4 epoch validation, verifies cloud forward, and renders crypto session metadata. |
| **Policies** (`Policies.tsx`) | Read policy table | `GET /api/v1/admin/policy` | Displays active signed policy versions and flow floors. Displays `.live-badge` when live. |
| **Audit Logs** (`AuditLogs.tsx`) | Filter decision logs | `GET /api/v1/admin/audit-logs` or `GET /api/v1/cloud/telemetry` | Displays real gateway audit records and cloud-stored events. Displays `.live-badge`. |
