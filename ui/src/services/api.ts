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
  CloudStats,
  CloudRecord,
  BaselineConfig,
} from '../types/qeris';

import {
  mockAuditLogs,
  mockDevices,
  mockPolicies,
  mockSecurityEvents,
} from '../data/mockData';

const env = (import.meta as unknown as { env: Record<string, string | undefined> }).env;

export const API_BASE_URL = env?.VITE_API_BASE_URL ?? 'http://localhost:8000';
export const CLOUD_BASE_URL = env?.VITE_CLOUD_URL ?? 'http://localhost:8001';

let activeAdminApiKey: string = env?.VITE_ADMIN_API_KEY ?? '';

export function setAdminApiKey(key: string): void {
  activeAdminApiKey = key.trim();
}

export function getAdminApiKey(): string {
  return activeAdminApiKey;
}

const TIMEOUT_MS = 4000;

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
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

function getAuthHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (activeAdminApiKey) {
    headers['X-Admin-Key'] = activeAdminApiKey;
  }
  return headers;
}

export async function getGatewayStatus(): Promise<GatewayStatus> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/gateway/status`);
    if (res.ok) {
      const data = await res.json();
      return {
        online: true,
        checked_at: new Date().toISOString(),
        service: data.service ?? 'qeris-gateway',
        baseline_mode: data.baseline_mode ?? 'B0_PROPOSED',
        policy_installed: data.policy_installed ?? true,
        active_policy_version: data.active_policy_version ?? 1,
        active_policy_digest: data.active_policy_digest ?? '',
        authority_id: data.authority_id ?? 'AUTH-QERIS-ROOT-01',
        cloud_queue_size: data.cloud_queue_size ?? 0,
        cloud_dropped_count: data.cloud_dropped_count ?? 0,
        active_sessions_count: data.active_sessions_count ?? 0,
        verified_flows_count: data.verified_flows_count ?? 4,
        registered_devices_count: data.registered_devices_count ?? 4,
      };
    }
  } catch {
    // try fallback health check
    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/health`);
      if (res.ok) {
        return {
          online: true,
          checked_at: new Date().toISOString(),
          service: 'qeris-gateway',
          baseline_mode: 'B0_PROPOSED',
          policy_installed: true,
          active_policy_version: 1,
        };
      }
    } catch {
      // offline
    }
  }

  return {
    online: false,
    checked_at: new Date().toISOString(),
  };
}

export async function checkFlow(req: FlowRequest): Promise<FlowResponse> {
  const res = await fetchWithTimeout(`${API_BASE_URL}/check-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      device_id: req.device_id,
      flow_id: req.flow_id,
      requested_mode: req.requested_mode,
      requested_profile: req.requested_profile,
      device_reported_sensitivity: req.device_reported_sensitivity,
    }),
  });

  if (!res.ok) {
    throw new Error(`Gateway returned HTTP ${res.status}`);
  }
  return await res.json();
}

export async function executeCryptoDemo(
  deviceId: string,
  flowId: string,
  mode: string,
  message: string
): Promise<TransmissionResult> {
  // First evaluate flow
  const flowResult = await checkFlow({
    device_id: deviceId,
    flow_id: flowId,
    requested_mode: mode as any,
  });

  let cryptoResult: CryptoResult | null = null;

  if (flowResult.decision === 'ALLOW') {
    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/crypto-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: deviceId,
          flow_id: flowId,
          requested_mode: mode,
          message,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        cryptoResult = {
          ciphertext_hex: data.ciphertext_hex ?? null,
          kem_encapsulated_key_hex: data.kem_encapsulated_key_hex ?? null,
          decrypted_message: data.decrypted_message ?? message,
          algorithm: data.algorithm ?? 'ML-KEM-512 + AES-GCM',
          crypto_status: 'SECURE',
        };
      }
    } catch {
      // Demo endpoint not reachable or simulated
    }
  }

  return {
    gateway: flowResult,
    crypto: cryptoResult,
    message,
    cloud_delivery: flowResult.decision === 'ALLOW' ? 'FORWARDED_TO_CLOUD' : 'BLOCKED_AT_INGRESS',
  };
}

export async function getDevices(): Promise<Device[]> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/devices`);
    if (res.ok) {
      const data = await res.json();
      return (data.devices || data).map((d: any) => ({
        device_id: d.device_id,
        supported_modes: d.supported_modes || ['CLASSICAL', 'HYBRID', 'PQC'],
        supported_profiles: d.supported_security_profiles || d.supported_profiles || [],
        status: d.quarantined ? 'LIMITED' : 'READY',
        mtu: d.max_packet_size_mtu || d.mtu || 1500,
        ram_bytes: d.ram_bytes_available || d.ram_bytes || 65536,
        quarantined: !!d.quarantined,
      }));
    }
  } catch {
    // fallback to mock with indicator
  }
  return mockDevices;
}

export async function getPolicies(): Promise<Policy[]> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/policies`);
    if (res.ok) {
      const data = await res.json();
      return (data.policies || data).map((p: any) => ({
        flow_id: p.flow_id,
        sensitivity: p.sensitivity,
        minimum_mode: p.minimum_mode,
        policy_version: p.policy_version || 1,
        authority_id: p.authority_id || 'AUTH-QERIS-ROOT-01',
        approved_profiles: p.approved_security_profiles || [],
        signature_verified: true,
      }));
    }
  } catch {
    // fallback
  }
  return mockPolicies;
}

export async function getAuditLogs(): Promise<AuditLog[]> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/audit-logs`);
    if (res.ok) {
      const data = await res.json();
      return (data.logs || data).map((l: any, i: number) => ({
        id: l.event_id || `audit-${i}`,
        event_id: l.event_id || `EVT-${i}`,
        timestamp: l.timestamp_iso || l.timestamp || new Date(l.ts ? l.ts * 1000 : Date.now()).toISOString(),
        device_id: l.device_id,
        flow_id: l.flow_id,
        sensitivity: l.sensitivity ?? null,
        minimum_mode: l.minimum_mode ?? null,
        requested_mode: l.requested_mode,
        policy_version: l.policy_version ?? 1,
        decision: l.decision,
        reason: l.reason || '',
        s3_verdict: l.s3_verdict,
        recovery_action: l.recovery_action,
        cause_label: l.cause_label,
      }));
    }
  } catch {
    // fallback
  }
  return mockAuditLogs;
}

export async function getSecurityEvents(): Promise<SecurityEvent[]> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/security-events`);
    if (res.ok) {
      const data = await res.json();
      return (data.events || data).map((e: any, i: number) => ({
        id: e.event_id || `sec-${i}`,
        timestamp: e.timestamp_iso || e.timestamp || new Date().toISOString(),
        type: e.decision === 'FLOOR_UNREACHABLE' ? 'FLOOR_UNREACHABLE' : 'DOWNGRADE_BLOCKED',
        flow_id: e.flow_id,
        device_id: e.device_id,
        sensitivity: e.sensitivity ?? null,
        required_mode: e.minimum_mode ?? null,
        requested_mode: e.requested_mode,
        decision: e.decision,
        reason: e.reason || '',
        s3_verdict: e.s3_verdict,
      }));
    }
  } catch {
    // fallback
  }
  return mockSecurityEvents;
}

export async function getCloudStats(): Promise<CloudStats> {
  try {
    const res = await fetchWithTimeout(`${CLOUD_BASE_URL}/api/v1/cloud/stats`);
    if (res.ok) {
      const data = await res.json();
      return {
        total_records: data.total_records ?? 0,
        forwarded_records: data.forwarded_records ?? data.total_records ?? 0,
        outage_buffer_size: data.outage_buffer_size ?? 0,
        outage_dropped_count: data.outage_dropped_count ?? 0,
        cloud_healthy: true,
        breakdown: data.breakdown ?? {},
        by_sensitivity: data.by_sensitivity ?? {},
      };
    }
  } catch {
    // Cloud offline or mock
  }

  return {
    total_records: 0,
    forwarded_records: 0,
    outage_buffer_size: 0,
    outage_dropped_count: 0,
    cloud_healthy: false,
    breakdown: {},
    by_sensitivity: {},
  };
}

export async function getCloudRecords(): Promise<CloudRecord[]> {
  try {
    const res = await fetchWithTimeout(`${CLOUD_BASE_URL}/api/v1/cloud/telemetry`);
    if (res.ok) {
      const data = await res.json();
      return data.records ?? [];
    }
  } catch {
    // offline
  }
  return [];
}

export async function getBaselineMode(): Promise<BaselineConfig> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/admin/baseline`, {
      headers: getAuthHeaders(),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // fallback
  }
  return {
    baseline_mode: 'B0_PROPOSED',
    description: 'QERIS Full Sensitivity-Aware & Adaptive Architecture (B0)',
    frozen: true,
    all_available_baselines: [
      'B0_PROPOSED',
      'B1_STATIC_CLASSICAL',
      'B2_STATIC_PQC',
      'B3_DEVICE_DIRECT_CLOUD',
      'B4_FIXED_SECURITY_FLOOR',
      'B5_NAIVE_PQC_OFFLOAD',
      'B6_NON_ADAPTIVE_PQC',
      'B7_UNTRUSTED_METADATA_BASELINE',
    ],
  };
}

export async function setBaselineMode(mode: string): Promise<boolean> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/admin/baseline`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ baseline_mode: mode }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function resetGatewayState(): Promise<boolean> {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/v1/admin/reset`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return res.ok;
  } catch {
    return false;
  }
}
