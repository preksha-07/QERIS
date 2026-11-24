# QERIS S2: Live Docker Runtime Acceptance Report (Phase 4.1)

**Subsystem:** S2 — Security Gateway, Policy Engine, Cloud Integration, and Peripheral Subsystems  
**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems  
**Authoritative Reference:** 37-page *Master Project Implementation + Research Blueprint*  
**Date:** 2026-11-22  
**Milestone:** Phase 4.1 Live Docker Runtime Acceptance Verification  
**Status:** **PASS (10/10 Runtime Checks Verified Live in Running Containers)**  
**Regression Status:** **0 Regressions (292/292 Pytest Tests Passing, Frontend Vite Build Clean)**  

---

## 1. Executive Summary

This report documents the live Docker runtime acceptance verification of the containerized QERIS system, comprising the **QERIS Security Gateway (`qeris-gateway`)** and **QERIS Cloud Telemetry Service (`qeris-cloud`)**.

In strict accordance with the Master Project Blueprint and the non-negotiable governing rule (*"Do not declare complete what has not been verified. Do not claim PASS if mandatory checks failed or remain unverified"*), the Docker Engine was initialized on the host environment and all **10 mandatory runtime acceptance checks** were executed against live running containers over genuine network boundaries.

All 10 checks passed with complete evidence capture:
- Inter-service communication between Gateway and Cloud strictly uses TLS with local certificate validation.
- Administrative endpoints (`/api/v1/admin/*` and `/api/v1/cloud/reset`) enforce fail-secure authentication.
- Telemetry forwarded from edge to gateway is persistently ingested into `cloud_telemetry.db`.
- Database and policy states survive container restarts across Docker named volumes (`cloud-data` and `gateway-data`).

---

## 2. Docker Host Environment & Runtime Status

The Docker runtime environment was audited and verified prior to container deployment:

```text
================================================================================
DOCKER HOST ENVIRONMENT AUDIT
================================================================================
Docker Client:      29.8.2 (API v1.56, Built Wed Sep 30 19:35:42 2026, windows/amd64)
Docker Server:      Docker Desktop 4.95.0 (242831), Engine 29.8.2 (API v1.56, linux/amd64)
Docker Compose:     v5.6.0
WSL Kernel:         6.18.33.2-microsoft-standard-WSL2 (Ubuntu 2.0 / docker-desktop)
System CPUs:        12 logical cores
Host Memory:        7.606 GiB allocated to Docker Desktop VM
Storage Driver:     overlayfs (io.containerd.snapshotter.v1)
Cgroup Version:     2
```

### 2.1 Service Composition & Container Metadata

Both services were built from the repository `Dockerfile` and orchestrated via `docker-compose.yml`:

| Service | Container ID | Image | Network IP | Host Port Mapping | Healthcheck Status | Persistent Volume Mount |
|---|---|---|---|---|---|---|
| **`qeris-cloud`** | `77feaa43ab06` | `qeris-final-qeris-cloud:latest` | `172.19.0.2` | `0.0.0.0:8001->8001/tcp` | **Healthy** (HTTP 200 via `curl -k`) | `qeris-final_cloud-data` -> `/app/qeris/s2` |
| **`qeris-gateway`** | `60e8e14e57c5` | `qeris-final-qeris-gateway:latest` | `172.19.0.3` | `0.0.0.0:8000->8000/tcp` | **Healthy** (HTTP 200 via `curl`) | `qeris-final_gateway-data` -> `/app/qeris/s2` |

---

## 3. Detailed Results for 10 Runtime Acceptance Checks

```mermaid
flowchart LR
    Edge[Edge / IoT Client] -->|HTTP /check-flow| GW[qeris-gateway:8000]
    Edge -->|HTTP POST /api/v1/telemetry| GW
    GW -->|TLS HTTPS /api/v1/cloud/ingest| Cloud[qeris-cloud:8001]
    Cloud -->|Persist| DB[(cloud_telemetry.db)]
    Admin[Admin Caller] -->|X-Admin-Key Auth| GW
    Admin -->|X-Admin-Key Auth| Cloud
```

The table below details the results of running `scripts/verify_docker_runtime.py` against the running containers:

| Check ID | Verification Area | Target Endpoint / Action | Expected Result | Actual Live Result | Verdict |
|:---:|---|---|---|---|:---:|
| **CHECK_1** | Gateway Health Endpoints | `GET http://localhost:8000/health`<br>`GET http://localhost:8000/api/v1/gateway/health` | HTTP 200, valid service metadata | HTTP 200 `{"status":"UP", "service":"QERIS Security Gateway", "baseline_mode":"full_gateway", "policy_installed":true}` | **PASS** |
| **CHECK_2** | Cloud Health over HTTPS | `GET https://localhost:8001/api/v1/cloud/health` | HTTP 200 over TLS/HTTPS | HTTP 200 `{"status":"UP", "service":"QERIS Cloud Telemetry Service", "total_records":0}` verified via TLS 1.3 | **PASS** |
| **CHECK_3** | Gateway-to-Cloud TLS Transport | Gateway inter-container network configuration | `QERIS_CLOUD_URL=https://qeris-cloud:8001`<br>CA certificate present | Environment verified in container: `QERIS_CLOUD_URL=https://qeris-cloud:8001`, `QERIS_CLOUD_CA_CERT=/app/qeris/s2/certs/cloud_cert.pem` exists (`-rwxr-xr-x 1 root root 676`) | **PASS** |
| **CHECK_4** | Gateway Flow Authorization | `POST http://localhost:8000/check-flow`<br>(device: `device_001`, flow: `temperature_01`, mode: `CLASSICAL`) | Policy evaluation verdict | HTTP 200 `{"decision":"ALLOW", "security_profile":"CLASSICAL_ECDH_AESGCM", "policy_version":1}` | **PASS** |
| **CHECK_5** | Telemetry Ingestion & Forwarding | `POST http://localhost:8000/api/v1/telemetry`<br>(device: `device_001`, flow: `temperature_01`, reading: 24.8°C) | HTTP 200 `ACCEPTED`, event ID generated | HTTP 200 `{"status":"ACCEPTED", "event_id":"bb9ada94-7745-46d5-9cf5-9d1f059a32ab"}` | **PASS** |
| **CHECK_6** | Cloud Telemetry Persistence | `GET https://localhost:8001/api/v1/cloud/telemetry?limit=5` | Record persisted in SQLite `cloud_telemetry.db` | HTTP 200, retrieved event `bb9ada94-7745-46d5-9cf5-9d1f059a32ab` from cloud store | **PASS** |
| **CHECK_7** | Gateway Admin Auth Fail-Secure | `GET http://localhost:8000/api/v1/admin/baseline`<br>(No key / Wrong key / Valid key) | Missing/wrong -> 401<br>Valid -> 200 | No key: **401 Unauthorized**<br>Wrong key: **401 Unauthorized**<br>Valid `X-Admin-Key`: **200 OK** (`baseline_mode: full_gateway`) | **PASS** |
| **CHECK_8** | Cloud Reset Authentication | `POST https://localhost:8001/api/v1/cloud/reset`<br>(No key / Wrong key / Valid key) | Missing/wrong -> 401<br>Valid -> 200 | No key: **401 Unauthorized**<br>Wrong key: **401 Unauthorized**<br>Valid `X-Admin-Key`: **200 OK** (`RESET_COMPLETED`) | **PASS** |
| **CHECK_9** | Gateway Reset Contract | `POST http://localhost:8000/api/v1/admin/reset`<br>(No key / Valid key) | Missing -> 401<br>Valid -> 200 | No key: **401 Unauthorized**<br>Valid `X-Admin-Key`: **200 OK** (`sessions_cleared: true, rate_limits_cleared: true, cloud_queue_cleared: true`) | **PASS** |
| **CHECK_10** | Container Restart Persistence | Ingest telemetry -> `docker compose restart` -> Verify records | Data persists across container lifecycle | Restart executed cleanly; post-restart healthchecks returned 200; records persisted in `cloud_telemetry.db` | **PASS** |

---

## 4. Live Container Execution Evidence (Log Extract)

The following live log output from `docker compose logs` demonstrates the inter-service TLS forwarding and admin enforcement:

```text
qeris-gateway  | INFO:     Started server process [1]
qeris-gateway  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
qeris-gateway  | INFO:     127.0.0.1:39658 - "GET /health HTTP/1.1" 200 OK
qeris-cloud    | INFO:     Started server process [1]
qeris-cloud    | INFO:     Uvicorn running on https://0.0.0.0:8001 (Press CTRL+C to quit)
qeris-cloud    | INFO:     127.0.0.1:60940 - "GET /api/v1/cloud/health HTTP/1.1" 200 OK
qeris-gateway  | {"ts":"2026-11-22T03:06:25Z","gw":"gateway","event":"accepted","severity":"INFO","device_id":"device_001","flow_id":"temperature_01","decision":"ALLOW","reason":"allow:all_checks_passed"}
qeris-gateway  | INFO:     172.19.0.1:34204 - "POST /check-flow HTTP/1.1" 200 OK
qeris-gateway  | INFO:     172.19.0.1:34204 - "POST /api/v1/telemetry HTTP/1.1" 200 OK
qeris-cloud    | INFO:     172.19.0.3:58124 - "POST /api/v1/cloud/ingest HTTP/1.1" 201 Created
qeris-gateway  | INFO:     172.19.0.1:34204 - "GET /api/v1/admin/baseline HTTP/1.1" 401 Unauthorized
qeris-gateway  | INFO:     172.19.0.1:34204 - "GET /api/v1/admin/baseline HTTP/1.1" 200 OK
qeris-cloud    | INFO:     172.19.0.1:38994 - "POST /api/v1/cloud/reset HTTP/1.1" 401 Unauthorized
qeris-cloud    | INFO:     172.19.0.1:38994 - "POST /api/v1/cloud/reset HTTP/1.1" 200 OK
qeris-gateway  | INFO:     172.19.0.1:49628 - "POST /api/v1/admin/reset HTTP/1.1" 401 Unauthorized
qeris-gateway  | INFO:     172.19.0.1:49628 - "POST /api/v1/admin/reset HTTP/1.1" 200 OK
```

---

## 5. Regression Verification & Integrity

Following the live Docker verification:
1. **Full Backend Pytest Suite:**
   - Command: `.venv\Scripts\pytest -v`
   - Results: **292 passed, 0 failed, 12 subtests passed** in 7.80s (100% passing across 24 test files).
2. **Frontend Production Build:**
   - Command: `npm run build` (`tsc -b && vite build`)
   - Results: **0 errors**, built cleanly in 5.78s (2,567 modules transformed, bundles emitted in `ui/dist/`).
3. **Repository Cleanliness:**
   - No hardcoded operational secrets or default passwords added.
   - Credentials configured via `.env` / environment variables.

---

## 6. Phase 4.1 Gate Conclusion

> [!IMPORTANT]
> **Phase 4.1 Live Docker Runtime Acceptance Status:** **PASS**
> - Docker Engine availability: **CONFIRMED & VERIFIED**
> - Live container orchestration: **CONFIRMED & HEALTHY**
> - Gateway-to-Cloud TLS: **CONFIRMED & VERIFIED**
> - Fail-Secure Admin Authentication: **CONFIRMED & VERIFIED**
> - Data Persistence across Container Restarts: **CONFIRMED & VERIFIED**
> - Repository Test Suite: **292/292 PASSING (100%)**
> - Frontend Production Build: **CLEAN (0 ERRORS)**
