import React, { useEffect, useState } from 'react';
import { Activity, Play, Search } from 'lucide-react';
import { FlowTable } from '../components/FlowTable';
import { FlowDetailModal } from '../components/FlowDetailModal';
import { SecurityEventCard } from '../components/SecurityEvent';
import { getAuditLogs, getSecurityEvents, checkFlow, checkFlowMock } from '../services/api';
import { demoScenarios } from '../data/mockData';
import { mockDevices, mockPolicies } from '../data/mockData';
import type { AuditLog, FlowResponse, SecurityEvent, SecurityMode } from '../types/qeris';
import { DecisionBadge, ModeBadge, SensitivityBadge } from '../components/SecurityBadge';

const SECURITY_MODES: SecurityMode[] = ['CLASSICAL', 'HYBRID', 'PQC'];

export const Flows: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  // ── Demo scenarios state ──────────────────────────────────────────────────
  const [activeScenario, setActiveScenario] = useState<number | null>(null);
  const [liveResult, setLiveResult] = useState<FlowResponse | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveMocked, setLiveMocked] = useState(false);

  // ── Custom flow check state ───────────────────────────────────────────────
  const [customDeviceId, setCustomDeviceId] = useState<string>(mockDevices[0].device_id);
  const [customFlowId, setCustomFlowId] = useState<string>(mockPolicies[0].flow_id);
  const [customMode, setCustomMode] = useState<SecurityMode>('CLASSICAL');
  const [customResult, setCustomResult] = useState<FlowResponse | null>(null);
  const [customLoading, setCustomLoading] = useState(false);
  const [customMocked, setCustomMocked] = useState(false);

  useEffect(() => {
    getAuditLogs().then(({ data }) => setLogs(data));
    getSecurityEvents().then(({ data }) => setEvents(data));
  }, []);

  // ── Demo scenario runner ──────────────────────────────────────────────────
  async function runScenario(index: number) {
    const scenario = demoScenarios[index];
    setActiveScenario(index);
    setLiveLoading(true);
    setLiveResult(null);

    const { data, error, mocked } = await checkFlow({
      device_id: scenario.device_id,
      flow_id: scenario.flow_id,
      requested_mode: scenario.requested as SecurityMode,
    });

    setLiveLoading(false);
    if (error || !data) {
      // Gateway unreachable — fall back to scenario mock result
      setLiveMocked(true);
      setLiveResult({
        flow_id: scenario.flow_id,
        sensitivity: scenario.sensitivity as import('../types/qeris').Sensitivity,
        minimum_mode: scenario.required as SecurityMode,
        policy_version: 1,
        authority_id: 'QERIS-GATEWAY',
        requested_mode: scenario.requested as SecurityMode,
        decision: scenario.decision,
        reason: scenario.reason,
      });
    } else {
      setLiveMocked(mocked);
      setLiveResult(data);
    }
  }

  // ── Custom flow check runner ──────────────────────────────────────────────
  // S4 integration point:
  //   When the real backend is ready, replace `checkFlowMock(request)` below
  //   with `await checkFlow(request)` — the FlowResponse shape is identical.
  async function runCustomCheck() {
    setCustomLoading(true);
    setCustomResult(null);

    const request = {
      device_id: customDeviceId,
      flow_id: customFlowId,
      requested_mode: customMode,
    };

    // Try the real gateway first; fall back to client-side mock if offline
    const { data, error } = await checkFlow(request);

    if (!error && data) {
      setCustomMocked(false);
      setCustomResult(data);
    } else {
      // S4: Remove this fallback once the real endpoint is available
      const { data: mockData } = checkFlowMock(request);
      setCustomMocked(true);
      setCustomResult(mockData);
    }

    setCustomLoading(false);
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

        {/* ── Custom Flow Check ─────────────────────────────────────────── */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Search size={14} color="var(--accent-cyan)" />
              Flow Check
            </span>
            {customMocked && customResult && (
              <span className="mock-badge">MOCK</span>
            )}
          </div>
          <div className="card-body">
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Select a device, flow, and requested security mode, then run the gateway check.
              Results come from the real gateway when online; falls back to client-side mock when offline.
            </p>

            {/* Selector row */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
                gap: 12,
                marginBottom: 16,
              }}
            >
              {/* Device */}
              <div>
                <label
                  htmlFor="fc-device"
                  style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.05em' }}
                >
                  DEVICE
                </label>
                <select
                  id="fc-device"
                  value={customDeviceId}
                  onChange={(e) => setCustomDeviceId(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: 'var(--text-primary)',
                    fontSize: 13,
                    padding: '7px 10px',
                    cursor: 'pointer',
                  }}
                >
                  {mockDevices.map((d) => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.device_id}
                    </option>
                  ))}
                </select>
              </div>

              {/* Flow */}
              <div>
                <label
                  htmlFor="fc-flow"
                  style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.05em' }}
                >
                  FLOW
                </label>
                <select
                  id="fc-flow"
                  value={customFlowId}
                  onChange={(e) => setCustomFlowId(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: 'var(--text-primary)',
                    fontSize: 13,
                    padding: '7px 10px',
                    cursor: 'pointer',
                  }}
                >
                  {mockPolicies.map((p) => (
                    <option key={p.flow_id} value={p.flow_id}>
                      {p.flow_id}
                    </option>
                  ))}
                </select>
              </div>

              {/* Requested Mode */}
              <div>
                <label
                  htmlFor="fc-mode"
                  style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.05em' }}
                >
                  REQUESTED MODE
                </label>
                <select
                  id="fc-mode"
                  value={customMode}
                  onChange={(e) => setCustomMode(e.target.value as SecurityMode)}
                  style={{
                    width: '100%',
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: 'var(--text-primary)',
                    fontSize: 13,
                    padding: '7px 10px',
                    cursor: 'pointer',
                  }}
                >
                  {SECURITY_MODES.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>

              {/* Run button aligned to bottom */}
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button
                  onClick={runCustomCheck}
                  disabled={customLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    width: '100%',
                    padding: '7px 14px',
                    background: customLoading ? 'var(--surface)' : 'var(--accent-cyan)',
                    color: customLoading ? 'var(--text-muted)' : '#000',
                    border: 'none',
                    borderRadius: 6,
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: customLoading ? 'not-allowed' : 'pointer',
                    justifyContent: 'center',
                    transition: 'opacity 0.15s',
                  }}
                >
                  <Play size={12} />
                  {customLoading ? 'Checking…' : 'Run Check'}
                </button>
              </div>
            </div>

            {/* Result area */}
            {!customResult && !customLoading && (
              <div className="empty-state" style={{ padding: '20px 0' }}>
                Select inputs and click Run Check to evaluate a flow.
              </div>
            )}

            {customLoading && (
              <div className="empty-state" style={{ padding: '20px 0' }}>
                <div
                  style={{
                    width: 20,
                    height: 20,
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

            {customResult && !customLoading && (
              <div
                style={{
                  borderTop: '1px solid var(--border)',
                  paddingTop: 14,
                  marginTop: 4,
                }}
              >
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
                  <div className="modal-row">
                    <span className="modal-key">Flow</span>
                    <span className="modal-val">{customResult.flow_id}</span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Decision</span>
                    <span className="modal-val">
                      <DecisionBadge decision={customResult.decision} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Sensitivity</span>
                    <span className="modal-val">
                      {customResult.sensitivity
                        ? <SensitivityBadge sensitivity={customResult.sensitivity} />
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Reason</span>
                    <span className="modal-val" style={{ fontSize: 11, color: 'var(--text-secondary)', textAlign: 'right', maxWidth: 200 }}>
                      {customResult.reason}
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Security Floor</span>
                    <span className="modal-val">
                      {customResult.minimum_mode
                        ? <ModeBadge mode={customResult.minimum_mode} />
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Policy Version</span>
                    <span className="modal-val">
                      {customResult.policy_version != null ? `v${customResult.policy_version}` : '—'}
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Requested Mode</span>
                    <span className="modal-val">
                      <ModeBadge mode={customResult.requested_mode} />
                    </span>
                  </div>
                  <div className="modal-row">
                    <span className="modal-key">Authority</span>
                    <span className="modal-val">
                      {customResult.authority_id ?? '—'}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Demo Scenarios ────────────────────────────────────────────── */}
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
