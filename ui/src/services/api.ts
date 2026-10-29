/**
 * QERIS API Service
 * All backend calls go through this module.
 * Mock data is used for endpoints not yet available.
 * The gateway remains the sole security authority.
 */

import type {
  FlowRequest,
  FlowResponse,
  AuditLog,
  Device,
  GatewayStatus,
  Policy,
  SecurityEvent,
  TransmissionResult,
  CryptoResult,
} from '../types/qeris';

import { SECURITY_LEVEL } from '../types/qeris';

import {
  mockAuditLogs,
  mockDevices,
  mockPolicies,
  mockSecurityEvents,
} from '../data/mockData';

// ─── Config ───────────────────────────────────────────────────────────────────

const API_BASE_URL =
  (import.meta as unknown as { env: { VITE_API_BASE_URL?: string } }).env
    .VITE_API_BASE_URL ?? 'http://localhost:8000';

const TIMEOUT_MS = 4000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ─── Gateway Status ───────────────────────────────────────────────────────────

export async function getGatewayStatus(): Promise<GatewayStatus> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/docs`, {
      method: 'HEAD',
    });
    return { online: res.ok || res.status === 200, checked_at: new Date().toISOString() };
  } catch {
    return { online: false, checked_at: new Date().toISOString() };
  }
}

// ─── check-flow (real endpoint) ───────────────────────────────────────────────

export async function checkFlow(
  request: FlowRequest
): Promise<{ data: FlowResponse | null; error: string | null; mocked: boolean }> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/check-flow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      return { data: null, error: `Gateway returned ${res.status}`, mocked: false };
    }

    const data: FlowResponse = await res.json();
    return { data, error: null, mocked: false };
  } catch {
    return { data: null, error: 'Gateway unreachable', mocked: false };
  }
}

// ─── check-flow mock (offline / no backend) ───────────────────────────────────
// Replicates the gateway decision logic client-side.
// S4: When the real backend is available, replace callers of checkFlowMock()
//     with checkFlow() — the FlowResponse shape is identical.

export function checkFlowMock(
  request: FlowRequest
): { data: FlowResponse; mocked: true } {
  const { device_id, flow_id, requested_mode } = request;

  const policy = mockPolicies.find((p) => p.flow_id === flow_id);
  const device = mockDevices.find((d) => d.device_id === device_id);

  // Unknown flow
  if (!policy) {
    return {
      data: {
        flow_id,
        sensitivity: null,
        minimum_mode: null,
        policy_version: null,
        authority_id: 'QERIS-GATEWAY',
        requested_mode,
        decision: 'REJECT',
        reason: 'Flow not found in policy registry',
      },
      mocked: true,
    };
  }

  // Unknown device
  if (!device) {
    return {
      data: {
        flow_id,
        sensitivity: policy.sensitivity,
        minimum_mode: policy.minimum_mode,
        policy_version: policy.policy_version,
        authority_id: policy.authority_id,
        requested_mode,
        decision: 'REJECT',
        reason: 'Device not registered',
      },
      mocked: true,
    };
  }

  const { sensitivity, minimum_mode, policy_version, authority_id } = policy;

  // Device cannot reach the security floor
  if (!device.supported_modes.includes(minimum_mode)) {
    return {
      data: {
        flow_id,
        sensitivity,
        minimum_mode,
        policy_version,
        authority_id,
        requested_mode,
        decision: 'FLOOR_UNREACHABLE',
        reason: 'Security floor is unreachable for this device',
      },
      mocked: true,
    };
  }

  // Device does not support the requested mode
  if (!device.supported_modes.includes(requested_mode)) {
    return {
      data: {
        flow_id,
        sensitivity,
        minimum_mode,
        policy_version,
        authority_id,
        requested_mode,
        decision: 'REJECT',
        reason: 'Device does not support the requested security mode',
      },
      mocked: true,
    };
  }

  // Requested mode is below the security floor
  if (SECURITY_LEVEL[requested_mode] < SECURITY_LEVEL[minimum_mode]) {
    return {
      data: {
        flow_id,
        sensitivity,
        minimum_mode,
        policy_version,
        authority_id,
        requested_mode,
        decision: 'REJECT',
        reason: 'Requested mode is below security floor',
      },
      mocked: true,
    };
  }

  // All checks passed
  return {
    data: {
      flow_id,
      sensitivity,
      minimum_mode,
      policy_version,
      authority_id,
      requested_mode,
      decision: 'ALLOW',
      reason: 'Policy and device capability satisfied',
    },
    mocked: true,
  };
}

// ─── Mock endpoints (future backend) ─────────────────────────────────────────
// These functions return mock data while the endpoints are not yet implemented.
// Replace the mock body with a real fetch call once the backend endpoints exist.

export async function getFlows(): Promise<{ data: Policy[]; mocked: boolean }> {
  // TODO: Replace with GET /flows when available
  await delay(120);
  return { data: mockPolicies, mocked: true };
}

export async function getDevices(): Promise<{ data: Device[]; mocked: boolean }> {
  // TODO: Replace with GET /devices when available
  await delay(80);
  return { data: mockDevices, mocked: true };
}

export async function getPolicies(): Promise<{ data: Policy[]; mocked: boolean }> {
  // TODO: Replace with GET /policies when available
  await delay(100);
  return { data: mockPolicies, mocked: true };
}

export async function getAuditLogs(): Promise<{ data: AuditLog[]; mocked: boolean }> {
  // TODO: Replace with GET /audit-logs when available
  await delay(150);
  return { data: mockAuditLogs, mocked: true };
}

export async function getSecurityEvents(): Promise<{
  data: SecurityEvent[];
  mocked: boolean;
}> {
  // TODO: Replace with GET /security-events when available
  await delay(100);
  return { data: mockSecurityEvents, mocked: true };
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── simulateTransmission ─────────────────────────────────────────────────────
// S4 INTEGRATION POINT:
//   1. Replace the checkFlow fallback inside this function with the real
//      POST /check-flow call once the backend is up.
//   2. If the decision is ALLOW, call POST /crypto-demo (or the S1 device
//      simulator endpoint) and populate the CryptoResult fields from the
//      real response. Remove the placeholder crypto stub below.
//
// The UI reads TransmissionResult and will automatically display real values
// when S4 fills them in — no UI changes required.

export async function simulateTransmission(
  request: FlowRequest,
  message: string
): Promise<{ result: TransmissionResult; mocked: boolean }> {
  // ── 1. Gateway policy check ─────────────────────────────────────────────
  // Try real backend first; fall back to client-side mock if offline.
  const { data: realData, error } = await checkFlow(request);

  let gatewayResponse: FlowResponse;
  let wasMocked: boolean;

  if (!error && realData) {
    gatewayResponse = realData;
    wasMocked = false;
  } else {
    // Offline fallback — replicate gateway logic client-side
    const { data: mockData } = checkFlowMock(request);
    gatewayResponse = mockData;
    wasMocked = true;
  }

  // ── 2. Crypto / data-path stage ─────────────────────────────────────────
  // S4: Replace this stub with a real call to POST /crypto-demo or the
  //     S1 device simulator. The CryptoResult shape matches what the UI needs.
  let cryptoResult: CryptoResult | null = null;

  if (gatewayResponse.decision === 'ALLOW') {
    // S4: Make the real API call here and populate cryptoResult from the response.
    // For now, show a placeholder that makes clear what WILL be here:
    cryptoResult = {
      ciphertext_hex: null,        // S4: populate from /crypto-demo response
      kem_encapsulated_key_hex: null, // S4: populate from /crypto-demo response
      decrypted_message: null,     // S4: populate from /crypto-demo response
      algorithm: 'ML-KEM-768 · HKDF-SHA256 · AES-256-GCM', // fixed — S1 suite
      crypto_status: 'UNAVAILABLE', // S4: set to 'SECURE' when backend connected
    };
  }

  return {
    result: {
      gateway: gatewayResponse,
      crypto: cryptoResult,
      message,
    },
    mocked: wasMocked,
  };
}
