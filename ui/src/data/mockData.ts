import {
  AuditLog,
  Decision,
  Device,
  DashboardStats,
  FailureRecovery,
  Policy,
  SecurityEvent,
} from '../types/qeris';

// ─── Mock Policies ───────────────────────────────────────────────────────────
// Mirrors policy.json exactly
export const mockPolicies: Policy[] = [
  {
    flow_id: 'temperature_01',
    sensitivity: 'LOW',
    minimum_mode: 'CLASSICAL',
    policy_version: 1,
    authority_id: 'QERIS-GATEWAY',
  },
  {
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    policy_version: 1,
    authority_id: 'QERIS-GATEWAY',
  },
];

// ─── Mock Devices ─────────────────────────────────────────────────────────────
// Mirrors devices.json exactly
export const mockDevices: Device[] = [
  {
    device_id: 'device_001',
    supported_modes: ['CLASSICAL', 'HYBRID'],
    status: 'READY',
  },
  {
    device_id: 'device_002',
    supported_modes: ['CLASSICAL', 'HYBRID', 'PQC'],
    status: 'READY',
  },
  {
    device_id: 'device_003',
    supported_modes: ['CLASSICAL'],
    status: 'LIMITED',
  },
];

// ─── Mock Audit Logs ─────────────────────────────────────────────────────────
// Based on real gateway_logs.jsonl data
export const mockAuditLogs: AuditLog[] = [
  {
    id: 'log-001',
    timestamp: '2026-10-27T12:42:11.000Z',
    device_id: 'device_002',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    requested_mode: 'CLASSICAL',
    policy_version: 1,
    decision: 'REJECT',
    reason: 'Requested mode is below security floor',
  },
  {
    id: 'log-002',
    timestamp: '2026-10-27T12:41:55.000Z',
    device_id: 'device_001',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    requested_mode: 'HYBRID',
    policy_version: 1,
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
  {
    id: 'log-003',
    timestamp: '2026-10-27T12:41:40.000Z',
    device_id: 'device_003',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    requested_mode: 'HYBRID',
    policy_version: 1,
    decision: 'FLOOR_UNREACHABLE',
    reason: 'Security floor is unreachable for this device',
  },
  {
    id: 'log-004',
    timestamp: '2026-10-27T12:40:18.000Z',
    device_id: 'device_001',
    flow_id: 'temperature_01',
    sensitivity: 'LOW',
    minimum_mode: 'CLASSICAL',
    requested_mode: 'CLASSICAL',
    policy_version: 1,
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
  {
    id: 'log-005',
    timestamp: '2026-10-27T12:39:52.000Z',
    device_id: 'device_002',
    flow_id: 'temperature_01',
    sensitivity: 'LOW',
    minimum_mode: 'CLASSICAL',
    requested_mode: 'PQC',
    policy_version: 1,
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
  {
    id: 'log-006',
    timestamp: '2026-10-27T12:38:30.000Z',
    device_id: 'device_002',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    requested_mode: 'CLASSICAL',
    policy_version: 1,
    decision: 'REJECT',
    reason: 'Requested mode is below security floor',
  },
  {
    id: 'log-007',
    timestamp: '2026-10-27T12:37:11.000Z',
    device_id: 'device_002',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    minimum_mode: 'HYBRID',
    requested_mode: 'PQC',
    policy_version: 1,
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
  {
    id: 'log-008',
    timestamp: '2026-10-27T12:35:05.000Z',
    device_id: 'device_003',
    flow_id: 'temperature_01',
    sensitivity: 'LOW',
    minimum_mode: 'CLASSICAL',
    requested_mode: 'CLASSICAL',
    policy_version: 1,
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
];

// ─── Mock Security Events ─────────────────────────────────────────────────────
export const mockSecurityEvents: SecurityEvent[] = [
  {
    id: 'evt-001',
    timestamp: '2026-10-27T12:42:11.000Z',
    type: 'DOWNGRADE_BLOCKED',
    flow_id: 'emergency_stop',
    device_id: 'device_002',
    sensitivity: 'CRITICAL',
    required_mode: 'HYBRID',
    requested_mode: 'CLASSICAL',
    decision: 'REJECT',
    reason: 'Requested mode is below security floor',
  },
  {
    id: 'evt-002',
    timestamp: '2026-10-27T12:41:40.000Z',
    type: 'FLOOR_UNREACHABLE',
    flow_id: 'emergency_stop',
    device_id: 'device_003',
    sensitivity: 'CRITICAL',
    required_mode: 'HYBRID',
    requested_mode: 'HYBRID',
    decision: 'FLOOR_UNREACHABLE',
    reason: 'Security floor is unreachable for this device',
  },
  {
    id: 'evt-003',
    timestamp: '2026-10-27T12:38:30.000Z',
    type: 'DOWNGRADE_BLOCKED',
    flow_id: 'emergency_stop',
    device_id: 'device_002',
    sensitivity: 'CRITICAL',
    required_mode: 'HYBRID',
    requested_mode: 'CLASSICAL',
    decision: 'REJECT',
    reason: 'Requested mode is below security floor',
  },
];

// ─── Dashboard Stats ──────────────────────────────────────────────────────────
export function computeStats(logs: AuditLog[]): DashboardStats {
  const decisions = logs.map((l) => l.decision);
  const allowed = decisions.filter((d) => d === 'ALLOW').length;
  const blocked = decisions.filter((d) => d === 'REJECT').length;
  const floorUnreachable = decisions.filter(
    (d) => d === 'FLOOR_UNREACHABLE'
  ).length;
  const securityEvents = blocked + floorUnreachable;
  const flowIds = new Set(logs.map((l) => l.flow_id));
  return {
    activeFlows: flowIds.size,
    allowed,
    blocked,
    securityEvents,
    floorUnreachable,
  };
}

// ─── Failure Recovery Classification ─────────────────────────────────────────
// NOTE: S3 recovery module is not yet implemented.
// This data is clearly labelled as demo/preparatory.
export const failureRecoveryData: FailureRecovery[] = [
  {
    failureClass: 'LOSS_TIMEOUT',
    label: 'Loss / Timeout',
    recommendedRecovery: 'Bounded retry with exponential backoff',
    securityFloorPreserved: true,
    available: false, // Prepared for S3 integration
  },
  {
    failureClass: 'MTU_FRAGMENTATION',
    label: 'MTU / Fragmentation',
    recommendedRecovery: 'Fragment reassembly or MTU negotiation',
    securityFloorPreserved: true,
    available: false,
  },
  {
    failureClass: 'RESOURCE_COMPUTE',
    label: 'Resource / Compute',
    recommendedRecovery: 'Defer or offload; reject if floor unmet',
    securityFloorPreserved: true,
    available: false,
  },
  {
    failureClass: 'SECURITY_FAILURE',
    label: 'Security Failure',
    recommendedRecovery: 'Reject, log, and quarantine device',
    securityFloorPreserved: true,
    available: true, // Implemented: gateway rejects and logs
  },
];

// ─── Demo Scenarios ───────────────────────────────────────────────────────────
export type DecisionResult = {
  label: string;
  device_id: string;
  flow_id: string;
  sensitivity: string;
  required: string;
  requested: string;
  decision: Decision;
  reason: string;
};

export const demoScenarios: DecisionResult[] = [
  {
    label: 'Scenario 1 — Valid Low-Sensitivity Flow',
    device_id: 'device_001',
    flow_id: 'temperature_01',
    sensitivity: 'LOW',
    required: 'CLASSICAL',
    requested: 'CLASSICAL',
    decision: 'ALLOW',
    reason: 'Policy and device capability satisfied',
  },
  {
    label: 'Scenario 2 — Downgrade Attempt Blocked',
    device_id: 'device_002',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    required: 'HYBRID',
    requested: 'CLASSICAL',
    decision: 'REJECT',
    reason: 'Requested mode is below security floor',
  },
  {
    label: 'Scenario 3 — Security Floor Unreachable',
    device_id: 'device_003',
    flow_id: 'emergency_stop',
    sensitivity: 'CRITICAL',
    required: 'HYBRID',
    requested: 'HYBRID',
    decision: 'FLOOR_UNREACHABLE',
    reason: 'Security floor is unreachable for this device',
  },
];
