import React, { useEffect, useState } from 'react';
import { Activity, Play } from 'lucide-react';
import { FlowTable } from '../components/FlowTable';
import { FlowDetailModal } from '../components/FlowDetailModal';
import { SecurityEventCard } from '../components/SecurityEvent';
import { getAuditLogs, getSecurityEvents, checkFlow } from '../services/api';
import { demoScenarios } from '../data/mockData';
import type { AuditLog, FlowResponse, SecurityEvent } from '../types/qeris';
import { DecisionBadge, ModeBadge, SensitivityBadge } from '../components/SecurityBadge';

export const Flows: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [activeScenario, setActiveScenario] = useState<number | null>(null);
  const [liveResult, setLiveResult] = useState<FlowResponse | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveMocked, setLiveMocked] = useState(false);

  useEffect(() => {
    getAuditLogs().then(({ data }) => setLogs(data));
    getSecurityEvents().then(({ data }) => setEvents(data));
  }, []);

  async function runScenario(index: number) {
    const scenario = demoScenarios[index];
    setActiveScenario(index);
    setLiveLoading(true);
    setLiveResult(null);

    const { data, error, mocked } = await checkFlow({
      device_id: scenario.device_id,
      flow_id: scenario.flow_id,
      requested_mode: scenario.requested as import('../types/qeris').SecurityMode,
    });

    setLiveLoading(false);
    if (error || !data) {
      // Gateway unreachable — fall back to scenario mock result
      setLiveMocked(true);
      setLiveResult({
        flow_id: scenario.flow_id,
        sensitivity: scenario.sensitivity as import('../types/qeris').Sensitivity,
        minimum_mode: scenario.required as import('../types/qeris').SecurityMode,
        policy_version: 1,
        authority_id: 'QERIS-GATEWAY',
        requested_mode: scenario.requested as import('../types/qeris').SecurityMode,
        decision: scenario.decision,
        reason: scenario.reason,
      });
    } else {
      setLiveMocked(mocked);
      setLiveResult(data);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Flow Monitor</h1>
        <p className="page-subtitle">
          Real-time evaluation of device flow requests against gateway policy
        </p>
      </div>

      <div className="page-body">
        {/* Demo Scenarios */}
        <div className="grid-2 section">
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Play size={14} color="var(--accent-cyan)" />
                Demo Scenarios
              </span>
            </div>
            <div className="card-body">
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                Run live requests against the gateway. Falls back to mock if gateway is offline.
              </p>
              <div className="demo-panel">
                {demoScenarios.map((s, i) => (
                  <button
                    key={i}
                    id={`demo-scenario-${i}`}
                    className={`demo-scenario-btn ${activeScenario === i ? 'active' : ''}`}
                    onClick={() => runScenario(i)}
                  >
                    <div>
                      <div className="demo-scenario-title">{s.label}</div>
                      <div className="demo-scenario-sub">
                        {s.flow_id} · {s.device_id} · {s.requested} → {s.decision}
                      </div>
                    </div>
                    <Play size={12} color="var(--accent-cyan)" />
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Live Result */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Activity size={14} color="var(--accent-cyan)" />
                Gateway Response
              </span>
              {liveMocked && liveResult && (
                <span className="mock-badge">MOCK</span>
              )}
            </div>
            <div className="card-body">
              {!liveResult && !liveLoading && (
                <div className="empty-state" style={{ padding: '30px 0' }}>
                  Select a scenario to run a live gateway check.
                </div>
              )}
              {liveLoading && (
                <div className="empty-state" style={{ padding: '30px 0' }}>
                  <div
                    style={{
                      width: 24,
                      height: 24,
                      border: '2px solid var(--border)',
                      borderTop: '2px solid var(--accent-cyan)',
                      borderRadius: '50%',
                      animation: 'spin 0.8s linear infinite',
                      margin: '0 auto 10px',
                    }}
                  />
                  Querying gateway…
                </div>
              )}
              {liveResult && !liveLoading && (
                <div>
                  <div className="modal-row">
                    <span className="modal-key">Flow</span>
                    <span className="modal-val">{liveResult.flow_id}</span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Sensitivity</span>
                    <span className="modal-val">
                      <SensitivityBadge sensitivity={liveResult.sensitivity} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Security Floor</span>
                    <span className="modal-val">
                      <ModeBadge mode={liveResult.minimum_mode} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Requested Mode</span>
                    <span className="modal-val">
                      <ModeBadge mode={liveResult.requested_mode} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Policy Version</span>
                    <span className="modal-val">v{liveResult.policy_version}</span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Authority</span>
                    <span className="modal-val">{liveResult.authority_id}</span>
                  </div>
                  <div
                    className="modal-row"
                    style={{ marginTop: 8, paddingTop: 12, borderTop: '1px solid var(--border)' }}
                  >
                    <span className="modal-key" style={{ fontSize: 13 }}>Decision</span>
                    <span className="modal-val">
                      <DecisionBadge decision={liveResult.decision} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Reason</span>
                    <span
                      className="modal-val"
                      style={{ fontFamily: 'inherit', fontSize: 11, color: 'var(--text-secondary)', textAlign: 'right', maxWidth: 200 }}
                    >
                      {liveResult.reason}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Security Events */}
        {events.length > 0 && (
          <div className="section">
            <div
              style={{
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: '0.06em',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                marginBottom: 10,
              }}
            >
              Security Events
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
                gap: 12,
              }}
            >
              {events.map((evt) => (
                <SecurityEventCard key={evt.id} event={evt} />
              ))}
            </div>
          </div>
        )}

        {/* Full Flow Table */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Activity size={14} color="var(--accent-cyan)" />
              All Flow Records
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {logs.length} records · click row for details
            </span>
          </div>
          <FlowTable logs={logs} onRowClick={(log) => setSelectedLog(log)} />
        </div>
      </div>

      {selectedLog && (
        <FlowDetailModal
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
        />
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
};
