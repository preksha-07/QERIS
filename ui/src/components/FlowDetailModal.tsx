import React from 'react';
import type { AuditLog } from '../types/qeris';
import { X } from 'lucide-react';
import { DecisionBadge, ModeBadge, SensitivityBadge } from './SecurityBadge';

interface FlowDetailModalProps {
  log: AuditLog;
  onClose: () => void;
}

export const FlowDetailModal: React.FC<FlowDetailModalProps> = ({
  log,
  onClose,
}) => {
  const time = new Date(log.timestamp).toLocaleString('en-US', {
    hour12: false,
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">{log.flow_id.toUpperCase()}</span>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">
          <div className="modal-row">
            <span className="modal-key">Timestamp</span>
            <span className="modal-val" style={{ fontSize: 11 }}>{time}</span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Device</span>
            <span className="modal-val">{log.device_id}</span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Sensitivity</span>
            <span className="modal-val">
              <SensitivityBadge sensitivity={log.sensitivity} />
            </span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Security Floor (Required)</span>
            <span className="modal-val">
              <ModeBadge mode={log.minimum_mode} />
            </span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Requested Mode</span>
            <span className="modal-val">
              <ModeBadge mode={log.requested_mode} />
            </span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Policy Version</span>
            <span className="modal-val">v{log.policy_version ?? '—'}</span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Decision</span>
            <span className="modal-val">
              <DecisionBadge decision={log.decision} />
            </span>
          </div>
          <div className="modal-row">
            <span className="modal-key">Reason</span>
            <span
              className="modal-val"
              style={{
                fontFamily: 'inherit',
                textAlign: 'right',
                maxWidth: 260,
                color: 'var(--text-secondary)',
                fontSize: 12,
              }}
            >
              {log.reason}
            </span>
          </div>

          {/* Security Floor Visual */}
          <div
            style={{
              marginTop: 16,
              padding: '12px',
              background: 'var(--bg-base)',
              borderRadius: 6,
              border: '1px solid var(--border)',
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: 'var(--text-muted)',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                marginBottom: 8,
                fontWeight: 600,
              }}
            >
              Security Floor Evaluation
            </div>
            <div className="floor-bar">
              <div
                className={`floor-segment ${
                  log.minimum_mode === 'CLASSICAL' ||
                  log.minimum_mode === 'HYBRID' ||
                  log.minimum_mode === 'PQC'
                    ? 'filled-classical'
                    : 'empty'
                }`}
              />
              <div
                className={`floor-segment ${
                  log.minimum_mode === 'HYBRID' || log.minimum_mode === 'PQC'
                    ? 'filled-hybrid'
                    : 'empty'
                }`}
              />
              <div
                className={`floor-segment ${
                  log.minimum_mode === 'PQC' ? 'filled-pqc' : 'empty'
                }`}
              />
            </div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: 9,
                color: 'var(--text-muted)',
                marginTop: 4,
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              <span>CLASSICAL</span>
              <span>HYBRID</span>
              <span>PQC</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
