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
