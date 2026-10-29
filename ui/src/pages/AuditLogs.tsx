import React, { useEffect, useState } from 'react';
import { ScrollText, Search } from 'lucide-react';
import { getAuditLogs } from '../services/api';
import { FlowDetailModal } from '../components/FlowDetailModal';
import { DecisionBadge, ModeBadge, SensitivityBadge } from '../components/SecurityBadge';
import type { AuditLog, Decision, Sensitivity } from '../types/qeris';

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<Decision | 'ALL'>('ALL');
  const [sensitivityFilter, setSensitivityFilter] = useState<Sensitivity | 'ALL'>('ALL');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  useEffect(() => {
    getAuditLogs().then(({ data }) => setLogs(data));
  }, []);

  const filtered = logs.filter((log) => {
    const matchSearch =
      !search ||
      log.flow_id.toLowerCase().includes(search.toLowerCase()) ||
      log.device_id.toLowerCase().includes(search.toLowerCase());
    const matchDecision =
      decisionFilter === 'ALL' || log.decision === decisionFilter;
    const matchSensitivity =
      sensitivityFilter === 'ALL' || log.sensitivity === sensitivityFilter;
    return matchSearch && matchDecision && matchSensitivity;
  });

  // Newest first
  const sorted = [...filtered].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  function formatTime(ts: string) {
    return new Date(ts).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Audit Logs</h1>
        <p className="page-subtitle">
          Complete, immutable record of all gateway decisions
        </p>
      </div>

      <div className="page-body">
        {/* Filters */}
        <div className="filter-row section">
          <div style={{ position: 'relative' }}>
            <Search
              size={13}
              style={{
                position: 'absolute',
                left: 10,
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)',
              }}
            />
            <input
              className="filter-input"
              style={{ paddingLeft: 30 }}
              type="text"
              placeholder="Search flow or device…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value as Decision | 'ALL')}
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="REJECT">REJECT</option>
            <option value="FLOOR_UNREACHABLE">FLOOR UNREACHABLE</option>
          </select>

          <select
            className="filter-select"
            value={sensitivityFilter}
            onChange={(e) =>
              setSensitivityFilter(e.target.value as Sensitivity | 'ALL')
            }
          >
            <option value="ALL">All Sensitivity</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>
            {sorted.length} records
          </span>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <ScrollText size={14} color="var(--accent-cyan)" />
              Gateway Decision Log
            </span>
            <span className="mock-badge">DEMO DATA</span>
          </div>

          {sorted.length === 0 ? (
            <div className="empty-state">No audit events recorded yet.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Device</th>
                    <th>Flow</th>
                    <th>Sensitivity</th>
                    <th>Required</th>
                    <th>Requested</th>
                    <th>Decision</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((log) => (
                    <tr key={log.id} onClick={() => setSelectedLog(log)}>
                      <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                        {formatTime(log.timestamp)}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                        {log.device_id}
                      </td>
                      <td className="mono">{log.flow_id}</td>
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
                      <td
                        style={{
                          fontSize: 11,
                          color: 'var(--text-muted)',
                          maxWidth: 200,
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                        title={log.reason}
                      >
                        {log.reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {selectedLog && (
        <FlowDetailModal
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
        />
      )}
    </div>
  );
};
