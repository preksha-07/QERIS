// QERIS Master Type Definitions
// Authoritative definitions matching the Master Blueprint and S2+S3 Backend.

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
  requested_profile?: string;
  device_reported_sensitivity?: Sensitivity;
  payload?: any;
}

export interface ReadinessEvaluation {
  device_id?: string;
  status?: string;
  can_support_pqc?: boolean;
  can_support_hybrid?: boolean;
  recommended_profile?: string;
  requires_fragmentation?: boolean;
  reason?: string;
}

export interface FlowResponse {
  flow_id: string;
  sensitivity: Sensitivity | null;
  minimum_mode: SecurityMode | null;
  policy_version: number | null;
  authority_id: string | null;
  requested_mode: SecurityMode;
  requested_profile?: string;
  decision: Decision;
  reason: string;
  baseline_mode?: string;
  adaptive_recovery?: boolean;
  floor_violation?: boolean;
  s3_verdict?: string;
  policy_digest?: string;
  readiness?: ReadinessEvaluation;
}

export interface Policy {
  flow_id: string;
  sensitivity: Sensitivity;
  minimum_mode: SecurityMode;
  policy_version: number;
  authority_id: string;
  approved_profiles?: string[];
  signature_verified?: boolean;
}

export interface Device {
  device_id: string;
  supported_modes: SecurityMode[];
  supported_profiles?: string[];
  status: DeviceStatus;
  mtu?: number;
  ram_bytes?: number;
  quarantined?: boolean;
}

export interface AuditLog {
  id?: string;
  event_id?: string;
  timestamp?: string;
  timestamp_iso?: string;
  ts?: number;
  device_id: string;
  flow_id: string;
  sensitivity: Sensitivity | null;
  minimum_mode: SecurityMode | null;
  requested_mode: SecurityMode;
  policy_version: number | null;
  decision: Decision;
  reason: string;
  s3_verdict?: string;
  recovery_action?: string;
  cause_label?: string;
  policy_epoch?: number;
}

export interface SecurityEvent {
  id: string;
  event_id?: string;
  timestamp: string;
  type: 'DOWNGRADE_BLOCKED' | 'FLOOR_UNREACHABLE' | 'UNKNOWN_FLOW' | 'QUARANTINE' | 'ALLOW';
  flow_id: string;
  device_id: string;
  sensitivity: Sensitivity | null;
  required_mode: SecurityMode | null;
  requested_mode: SecurityMode;
  decision: Decision;
  reason: string;
  s3_verdict?: string;
  recovery_action?: string;
}

export interface GatewayStatus {
  online: boolean;
  checked_at: string;
  service?: string;
  baseline_mode?: string;
  policy_installed?: boolean;
  active_policy_version?: number;
  active_policy_digest?: string;
  authority_id?: string;
  cloud_queue_size?: number;
  cloud_dropped_count?: number;
  active_sessions_count?: number;
  verified_flows_count?: number;
  registered_devices_count?: number;
}

export interface DashboardStats {
  activeFlows: number;
  allowed: number;
  blocked: number;
  securityEvents: number;
  floorUnreachable: number;
}

export interface CloudStats {
  total_records: number;
  forwarded_records: number;
  outage_buffer_size: number;
  outage_dropped_count: number;
  cloud_healthy: boolean;
  breakdown: Record<string, number>;
  by_sensitivity: Record<string, number>;
}

export interface CloudRecord {
  id?: number;
  event_id: string;
  device_id: string;
  flow_id: string;
  timestamp: number;
  sensitivity: string;
  security_profile: string;
  policy_version: number;
  policy_digest: string;
  payload: any;
  gateway_decision: string;
  received_at?: number;
}

export interface BaselineConfig {
  status?: string;
  baseline_mode: string;
  description: string;
  recovery_properties?: Record<string, any>;
  frozen: boolean;
  all_available_baselines?: string[];
}

export interface CryptoResult {
  ciphertext_hex: string | null;
  kem_encapsulated_key_hex: string | null;
  decrypted_message: string | null;
  algorithm: string | null;
  crypto_status: 'SECURE' | 'DEGRADED' | 'UNAVAILABLE' | null;
}

export interface TransmissionResult {
  gateway: FlowResponse;
  crypto: CryptoResult | null;
  message: string;
  telemetry_status?: string;
  cloud_delivery?: string;
  event_id?: string;
  queue_size?: number;
}

// S3 Failure Recovery Taxonomy
export type FailureClass =
  | 'SECURITY_FAILURE'
  | 'MTU_FRAGMENTATION'
  | 'LOSS_TIMEOUT'
  | 'RESOURCE_COMPUTE'
  | 'CAUSE_UNKNOWN';

export interface FailureRecovery {
  failureClass: FailureClass;
  label: string;
  recommendedRecovery: string;
  securityFloorPreserved: boolean;
  available: boolean;
}

export type RecoveryAction =
  | 'RETRY'
  | 'REFRAGMENT'
  | 'EXTEND_TIMEOUT'
  | 'OBSERVE_AND_WAIT'
  | 'FAIL'
  | 'DISCARD_AND_LOG';

export interface S3TaxonomyItem {
  failureClass: FailureClass;
  title: string;
  description: string;
  action: RecoveryAction;
  floorSafety: string;
  provenance: string;
}
