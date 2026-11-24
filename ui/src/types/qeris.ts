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
  baseline_mode?: string;
  adaptive_recovery?: boolean;
  floor_violation?: boolean;
  s3_verdict?: string;
  policy_digest?: string;
  readiness?: {
    device_id?: string;
    status?: string;
    can_support_pqc?: boolean;
    can_support_hybrid?: boolean;
    recommended_profile?: string;
    requires_fragmentation?: boolean;
    reason?: string;
  };
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
  service?: string;
  baseline_mode?: string;
  policy_installed?: boolean;
  active_policy_version?: number;
  active_policy_digest?: string;
  cloud_queue_size?: number;
  cloud_dropped_count?: number;
  active_sessions_count?: number;
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
  breakdown: Record<string, number>;
  by_sensitivity: Record<string, number>;
}

export interface CloudRecord {
  id: number;
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
  received_at: number;
}

export interface BaselineConfig {
  status?: string;
  baseline_mode: string;
  description: string;
  recovery_properties?: Record<string, any>;
  frozen: boolean;
  all_available_baselines?: string[];
}

// ─── Transmission / Crypto Result ─────────────────────────────────────────────
// Populated by S4 when the real backend + S1 crypto layer is connected.
// The UI displays these fields when present; they are null/undefined offline.
export interface CryptoResult {
  /** Hex-encoded ciphertext (AES-256-GCM output from S1) */
  ciphertext_hex: string | null;
  /** Hex-encoded encapsulated KEM key used for this transmission */
  kem_encapsulated_key_hex: string | null;
  /** The decrypted/received plaintext message confirmed by the gateway */
  decrypted_message: string | null;
  /** Algorithm suite used, e.g. "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM" */
  algorithm: string | null;
  /** Crypto/transmission status label */
  crypto_status: 'SECURE' | 'DEGRADED' | 'UNAVAILABLE' | null;
}

// ─── Full transmission result (gateway decision + optional crypto) ─────────────
export interface TransmissionResult {
  /** The gateway's policy decision */
  gateway: FlowResponse;
  /** Crypto/data-path result — null until S4 connects the backend + S1 */
  crypto: CryptoResult | null;
  /** The original user-entered message */
  message: string;
  /** Telemetry delivery status if forwarded to cloud */
  telemetry_status?: string;
  /** Cloud delivery state e.g. FORWARDED_TO_CLOUD or QUEUED_FOR_CLOUD */
  cloud_delivery?: string;
  /** Unique telemetry event ID */
  event_id?: string;
  /** Outage buffer queue size */
  queue_size?: number;
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
