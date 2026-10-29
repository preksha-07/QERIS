import React from 'react';
import type { AuditLog } from '../types/qeris';
import { DecisionBadge, ModeBadge, SensitivityBadge } from './SecurityBadge';

interface FlowTableProps {
  logs: AuditLog[];
  onRowClick?: (log: AuditLog) => void;
}

export const FlowTable: React.FC<FlowTableProps> = ({ logs, onRowClick }) => {
  if (logs.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
        </div>
        No flow records to display.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Flow</th>
            <th>Device</th>
            <th>Sensitivity</th>
            <th>Required</th>
            <th>Requested</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} onClick={() => onRowClick?.(log)}>
              <td className="mono">{log.flow_id}</td>
              <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                {log.device_id}
              </td>
              <td>
                <SensitivityBadge sensitivity={log.sensitivity} />
              </td>
              <td>
                <ModeBadge mode={log.minimum_mode} />
              </td>
              <td>
                <ModeBadge mode={log.requested_mode} />
              </td>
              <td>
                <DecisionBadge decision={log.decision} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
