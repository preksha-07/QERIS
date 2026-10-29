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
} from '../types/qeris';

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
