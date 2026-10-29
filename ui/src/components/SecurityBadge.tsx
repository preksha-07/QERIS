import React from 'react';
import type { Decision, Sensitivity, SecurityMode } from '../types/qeris';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  Shield,
  ShieldCheck,
} from 'lucide-react';

// ─── Decision Badge ───────────────────────────────────────────────────────────

interface DecisionBadgeProps {
  decision: Decision;
}

export const DecisionBadge: React.FC<DecisionBadgeProps> = ({ decision }) => {
  if (decision === 'ALLOW') {
    return (
      <span className="badge badge-allow">
        <CheckCircle size={10} />
        ALLOW
      </span>
    );
  }
  if (decision === 'REJECT') {
    return (
      <span className="badge badge-reject">
        <XCircle size={10} />
        REJECT
      </span>
    );
  }
  return (
    <span className="badge badge-floor">
      <AlertTriangle size={10} />
      FLOOR UNREACHABLE
    </span>
  );
};

// ─── Sensitivity Badge ────────────────────────────────────────────────────────

interface SensitivityBadgeProps {
  sensitivity: Sensitivity | null;
}

export const SensitivityBadge: React.FC<SensitivityBadgeProps> = ({
  sensitivity,
}) => {
  if (!sensitivity) return <span className="text-muted">—</span>;
  const cls =
    sensitivity === 'CRITICAL'
      ? 'badge-critical'
      : sensitivity === 'HIGH'
      ? 'badge-high'
      : sensitivity === 'MEDIUM'
      ? 'badge-medium'
      : 'badge-low';
  const icon =
    sensitivity === 'CRITICAL' ? (
      <ShieldAlert size={10} />
    ) : sensitivity === 'HIGH' ? (
      <Shield size={10} />
    ) : (
      <ShieldCheck size={10} />
    );
  return (
    <span className={`badge ${cls}`}>
      {icon}
      {sensitivity}
    </span>
  );
};

// ─── Security Mode Badge ──────────────────────────────────────────────────────

interface ModeBadgeProps {
  mode: SecurityMode | null;
}

export const ModeBadge: React.FC<ModeBadgeProps> = ({ mode }) => {
  if (!mode) return <span className="text-muted">—</span>;
  const cls =
    mode === 'PQC'
      ? 'badge-pqc'
      : mode === 'HYBRID'
      ? 'badge-hybrid'
      : 'badge-classical';
  return <span className={`badge ${cls}`}>{mode}</span>;
};
