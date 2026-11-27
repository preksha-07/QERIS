import React, { useEffect, useState } from 'react';
import {
  Filter,
  Search,
  ChevronRight,
  X,
} from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getAuditLogs } from '../services/api';
import type { GatewayStatus, AuditLog } from '../types/qeris';

export const Flows: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const fetchData = async () => {
    const [gwStatus, auditLogs] = await Promise.all([
      getGatewayStatus(),
      getAuditLogs(),
    ]);
    setStatus(gwStatus);
    setLogs(auditLogs);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const filteredLogs = logs.filter((log) => {
    const matchesDecision = filterDecision === 'ALL' || log.decision === filterDecision;
    const matchesSearch =
      searchTerm === '' ||
      log.flow_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.device_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.reason.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesDecision && matchesSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Live Flow Monitor"
        description="Comprehensive audit of all active network flows and real-time gateway policy decisions"
      />

      <div className="main-content">
        {/* Controls and Filters */}
        <div className="qeris-card" style={{ marginBottom: 20, padding: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 360 }}>
                <Search size={15} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter by Flow ID, Device ID, or reason..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="qeris-input"
                  style={{ paddingLeft: 32 }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Filter size={15} color="var(--text-muted)" />
                <select
                  value={filterDecision}
                  onChange={(e) => setFilterDecision(e.target.value)}
                  className="qeris-select"
                  style={{ width: 170 }}
                >
                  <option value="ALL">All Decisions</option>
                  <option value="ALLOW">ALLOW Only</option>
                  <option value="REJECT">REJECT Only</option>
                  <option value="FLOOR_UNREACHABLE">FLOOR_UNREACHABLE</option>
                </select>
              </div>
            </div>

            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Showing <strong>{filteredLogs.length}</strong> of <strong>{logs.length}</strong> events
            </div>
          </div>
        </div>

        {/* Flows Table */}
        <div className="qeris-card" style={{ padding: 0 }}>
          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Event ID / Timestamp</th>
                  <th>Device ID</th>
                  <th>Flow ID</th>
                  <th>Sensitivity</th>
                  <th>Minimum Req</th>
                  <th>Requested</th>
                  <th>Decision</th>
                  <th>S3 Verdict</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                      No flows matching filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log, idx) => (
                    <tr
                      key={log.id || idx}
                      onClick={() => setSelectedLog(log)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <div className="mono" style={{ fontSize: 11, fontWeight: 600 }}>
                          {log.event_id || `EVT-${idx}`}
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}
                        </div>
                      </td>
                      <td className="mono" style={{ fontWeight: 600 }}>{log.device_id}</td>
                      <td className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {log.flow_id}
                      </td>
                      <td>
                        <span className={`qeris-badge ${
                          log.sensitivity === 'CRITICAL' || log.sensitivity === 'HIGH'
                            ? 'badge-reject'
                            : 'badge-neutral'
                        }`}>
                          {log.sensitivity ?? 'UNMAPPED'}
                        </span>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11 }}>
                          {log.minimum_mode ?? 'NONE'}
                        </span>
                      </td>
                      <td>
                        <span className="qeris-badge badge-neutral mono" style={{ fontSize: 10.5 }}>
                          {log.requested_mode}
                        </span>
                      </td>
                      <td>
                        <span className={`qeris-badge ${
                          log.decision === 'ALLOW'
                            ? 'badge-allow'
                            : log.decision === 'REJECT'
                            ? 'badge-reject'
                            : 'badge-unreachable'
                        }`}>
                          {log.decision}
                        </span>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--status-observe)' }}>
                          {log.s3_verdict || 'NOMINAL'}
                        </span>
                      </td>
                      <td>
                        <button className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: 11 }}>
                          Inspect <ChevronRight size={12} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Slide-out Flow Detail Modal */}
      {selectedLog && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.4)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'flex-end',
          zIndex: 50,
        }}>
          <div style={{
            width: 460,
            background: '#ffffff',
            height: '100%',
            boxShadow: 'var(--shadow-xl)',
            display: 'flex',
            flexDirection: 'column',
            padding: 24,
            overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div>
                <h3 style={{ fontSize: 16, fontWeight: 700 }}>Flow Audit Inspection</h3>
                <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>Event Record {selectedLog.event_id}</p>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: '#f8fafc', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Gateway Policy Decision
                </div>
                <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`qeris-badge ${
                    selectedLog.decision === 'ALLOW'
                      ? 'badge-allow'
                      : selectedLog.decision === 'REJECT'
                      ? 'badge-reject'
                      : 'badge-unreachable'
                  }`} style={{ fontSize: 13, padding: '4px 10px' }}>
                    {selectedLog.decision}
                  </span>
                </div>
                <p style={{ fontSize: 12, marginTop: 8, color: 'var(--text-secondary)' }}>
                  <strong>Reason:</strong> {selectedLog.reason}
                </p>
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  FLOW PARAMETERS
                </div>
                <div className="qeris-table-container">
                  <table className="qeris-table" style={{ fontSize: 12 }}>
                    <tbody>
                      <tr>
                        <td style={{ color: 'var(--text-muted)', width: 140 }}>Flow Identifier</td>
                        <td className="mono" style={{ fontWeight: 600 }}>{selectedLog.flow_id}</td>
                      </tr>
                      <tr>
                        <td style={{ color: 'var(--text-muted)' }}>Device Origin</td>
                        <td className="mono">{selectedLog.device_id}</td>
                      </tr>
                      <tr>
                        <td style={{ color: 'var(--text-muted)' }}>Flow Sensitivity</td>
                        <td>{selectedLog.sensitivity ?? 'UNMAPPED'}</td>
                      </tr>
                      <tr>
                        <td style={{ color: 'var(--text-muted)' }}>Policy Floor Req</td>
                        <td className="mono">{selectedLog.minimum_mode ?? 'NONE'}</td>
                      </tr>
                      <tr>
                        <td style={{ color: 'var(--text-muted)' }}>Requested Mode</td>
                        <td className="mono">{selectedLog.requested_mode}</td>
                      </tr>
                      <tr>
                        <td style={{ color: 'var(--text-muted)' }}>Policy Epoch</td>
                        <td className="mono">v{selectedLog.policy_version ?? 1}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  S3 ADAPTIVE RECOVERY CLASSIFICATION
                </div>
                <div style={{ background: '#f5f3ff', border: '1px solid #ddd6fe', borderRadius: 8, padding: 12 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--status-observe)' }}>
                    Verdict: {selectedLog.s3_verdict || 'NOMINAL_FLOW'}
                  </div>
                  <div style={{ fontSize: 11, color: '#6d28d9', marginTop: 4 }}>
                    Recovery Action: {selectedLog.recovery_action || 'NONE_REQUIRED'}
                  </div>
                  {selectedLog.cause_label && (
                    <div style={{ fontSize: 10, color: '#7c3aed', marginTop: 4 }} className="mono">
                      Taxonomy Cause: {selectedLog.cause_label}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
