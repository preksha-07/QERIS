# QERIS Frontend Dashboard & Experimental Interface

This directory contains the React/TypeScript/Vite web application for the **Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway for Heterogeneous IoT Edge-Cloud Systems (QERIS)**.

## 1. Architecture Overview

The UI provides real-time visualization and experimental controls for the QERIS Gateway without usurping security authority:
- **Dashboard (`/`)**: Displays real-time gateway health, active baseline mode (B1–B7), monotonic signed policy version, cloud outage buffer queue status, and decision distribution pie chart.
- **Flow Monitor (`/flows`)**: Real-time evaluation of device flow requests against gateway policy via `POST /check-flow`, supporting custom flow checks and 4 pre-configured demo benchmark scenarios.
- **Devices (`/devices`)**: Gateway capability registry view and End-to-End Transmission Simulator (`POST /check-flow` -> `POST /api/v1/telemetry`), displaying session crypto results (ML-KEM-768 + AES-256-GCM) and cloud forwarding state.
- **Policies (`/policies`)**: Visualizes active security floor policies (Classical, Hybrid, PQC) and monotonic version digests.
- **Security & Recovery (`/security`)**: Explains cause-classified, security-floor-bounded recovery architecture, cryptographic algorithm stack, and S3 failure classifications.
- **Audit Logs (`/audit`)**: Immutable log table of all gateway decisions and cloud-forwarded records with multi-criteria filtering.

---

## 2. Security Invariants & Integration Principles

1. **Gateway as Sole Authority:**
   All policy evaluations, capability checks, and cryptographic profiles are decided exclusively by the backend gateway. The frontend never computes decisions or negotiates floors.
2. **Zero Hardcoded Secrets:**
   No secrets or API keys are embedded in frontend source files, bundles, or local storage. Administrative access uses ephemeral session memory (`setAdminApiKey`) or optional local environment variables (`VITE_ADMIN_API_KEY`).
3. **Fail-Secure Admin Authentication:**
   - Unconfigured Gateway: `HTTP 403 Forbidden` (administrative endpoints disabled).
   - Configured Gateway with Invalid/Missing Key: `HTTP 401 Unauthorized`.
   - Valid Matching Key (`X-Admin-Key` header): `HTTP 200 OK`.
4. **Visual Separation of Live vs Mock Data:**
   The UI clearly identifies data provenance via `.live-badge` (`LIVE BACKEND CONNECTED` / `LIVE AUDIT LOGS`) and `.mock-badge` (`OFFLINE / SAMPLE DATA`).

---

## 3. Configuration & Environment Variables

Create a `.env` file in `ui/` or the project root (copied from `.env.example`):

```bash
# Gateway API URL (defaults to http://localhost:8000)
VITE_API_BASE_URL=http://localhost:8000

# Cloud Telemetry URL (defaults to https://localhost:8001)
VITE_CLOUD_URL=https://localhost:8001

# Optional: Admin API Key for baseline switching in development
VITE_ADMIN_API_KEY=
```

---

## 4. Local Development & Proxying

The Vite development server runs on port `5173` and includes built-in proxying to eliminate browser CORS and self-signed certificate warnings during development:
- `/check-flow` -> `http://localhost:8000/check-flow`
- `/health` -> `http://localhost:8000/health`
- `/api/v1` -> `http://localhost:8000/api/v1`
- `/api/v1/cloud` -> `https://localhost:8001/api/v1/cloud` (`secure: false` for self-signed certificates)

### Running Locally

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start development server:**
   ```bash
   npm run dev
   ```

3. **Build production bundle:**
   ```bash
   npm run build
   ```
