// QERIS Type Definitions
// These interfaces mirror the real backend data structures.

export type SecurityMode = 'CLASSICAL' | 'HYBRID' | 'PQC';
export type Decision = 'ALLOW' | 'REJECT' | 'FLOOR_UNREACHABLE';
export type Sensitivity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DeviceStatus = 'READY' | 'LIMITED' | 'OFFLINE';

export const SECURITY_LEVEL: Record<SecurityMode, number> = {
  CLASSICAL: 1,
  HYBRID: 2,
  PQC: 3,
};

export interface FlowRequest {
  device_id: string;
  flow_id: string;
  requested_mode: SecurityMode;
}

export interface FlowResponse {
  flow_id: string;
  sensitivity: Sensitivity | null;
  minimum_mode: SecurityMode | null;
  policy_version: number | null;
  authority_id: string | null;
  requested_mode: SecurityMode;
  decision: Decision;
  reason: string;
}

export interface Policy {
  flow_id: string;
  sensitivity: Sensitivity;
  minimum_mode: SecurityMode;
  policy_version: number;
  authority_id: string;
}

export interface Device {
  device_id: string;
  supported_modes: SecurityMode[];
  status: DeviceStatus;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  device_id: string;
  flow_id: string;
  sensitivity: Sensitivity | null;
  minimum_mode: SecurityMode | null;
  requested_mode: SecurityMode;
  policy_version: number | null;
  decision: Decision;
  reason: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'DOWNGRADE_BLOCKED' | 'FLOOR_UNREACHABLE' | 'UNKNOWN_FLOW' | 'ALLOW';
  flow_id: string;
  device_id: string;
  sensitivity: Sensitivity | null;
  required_mode: SecurityMode | null;
  requested_mode: SecurityMode;
  decision: Decision;
  reason: string;
}

export interface GatewayStatus {
  online: boolean;
  checked_at: string;
}

export interface DashboardStats {
  activeFlows: number;
  allowed: number;
  blocked: number;
  securityEvents: number;
  floorUnreachable: number;
}

// Failure classification for S3 / future recovery module
export type FailureClass =
  | 'LOSS_TIMEOUT'
  | 'MTU_FRAGMENTATION'
  | 'RESOURCE_COMPUTE'
  | 'SECURITY_FAILURE';

export interface FailureRecovery {
  failureClass: FailureClass;
  label: string;
  recommendedRecovery: string;
  securityFloorPreserved: boolean;
  available: boolean; // false = future/mock
}
