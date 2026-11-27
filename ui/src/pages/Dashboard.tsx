import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  GitBranch,
  CheckCircle,
  ArrowDown,
  Lock,
  Radio,
  RefreshCw,
  Key,
} from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { SecurityEventCard } from '../components/SecurityEvent';
import { FlowTable } from '../components/FlowTable';
import { FlowDetailModal } from '../components/FlowDetailModal';
import {
  getAuditLogs,
  getSecurityEvents,
  getGatewayStatus,
  getBaselineMode,
  setBaselineMode,
  resetGatewayState,
  setAdminApiKey,
  getAdminApiKey,
} from '../services/api';
import { computeStats } from '../data/mockData';
import type { AuditLog, SecurityEvent, GatewayStatus, BaselineConfig } from '../types/qeris';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface DashboardProps {
  gatewayOnline: boolean;
}

const DECISION_COLORS: Record<string, string> = {
  ALLOW: '#10b981',
  REJECT: '#ef4444',
  FLOOR_UNREACHABLE: '#f59e0b',
};

const BASELINES = [
  { id: 'static_classical', label: 'B1: Static Classical' },
  { id: 'static_hybrid', label: 'B2: Static Hybrid' },
  { id: 'static_pqc', label: 'B3: Static PQC' },
  { id: 'sensitivity_only', label: 'B4: Sensitivity-Only' },
  { id: 'downgrade_on_failure', label: 'B5: Downgrade-on-Failure' },
  { id: 'static_retry_with_floor', label: 'B6: Static Retry with Floor' },
  { id: 'full_gateway', label: 'B7: Full QERIS' },
];

export const Dashboard: React.FC<DashboardProps> = ({ gatewayOnline }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [isLogsMocked, setIsLogsMocked] = useState<boolean>(true);

  // Gateway operational state
  const [gwStatus, setGwStatus] = useState<GatewayStatus | null>(null);
  const [baselineConfig, setBaselineConfig] = useState<BaselineConfig | null>(null);
  const [selectedBaseline, setSelectedBaseline] = useState<string>('full_gateway');
  const [baselineUpdating, setBaselineUpdating] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Admin key UI control
  const [adminKeyInput, setAdminKeyInput] = useState<string>(getAdminApiKey());
  const [showAdminKeyBox, setShowAdminKeyBox] = useState<boolean>(false);

  const refreshData = async () => {
    const logData = await getAuditLogs();
    setLogs(logData);
    setIsLogsMocked(false);

    const evtData = await getSecurityEvents();
    setEvents(evtData);

    const status = await getGatewayStatus();
    setGwStatus(status);

    const baseCfg = await getBaselineMode();
    setBaselineConfig(baseCfg);
    if (baseCfg.baseline_mode) {
      setSelectedBaseline(baseCfg.baseline_mode);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleBaselineChange = async () => {
    setBaselineUpdating(true);
    setStatusMessage(null);
    const ok = await setBaselineMode(selectedBaseline);
    setBaselineUpdating(false);

    if (ok) {
      setStatusMessage(`Baseline mode successfully updated to ${selectedBaseline}`);
      await refreshData();
    } else {
      setStatusMessage('Failed to update baseline (Admin credentials required)');
    }
  };

  const handleAdminKeySave = () => {
    setAdminApiKey(adminKeyInput);
    setStatusMessage('Admin API key updated for current UI session.');
    refreshData();
  };

  const handleResetState = async () => {
    if (!window.confirm('Reset gateway experiment state (rate limits, sessions, and cloud queue)?')) {
      return;
    }
    const ok = await resetGatewayState();
    setStatusMessage(ok ? 'Gateway reset successful' : 'Gateway reset failed');
    await refreshData();
  };

  const stats = computeStats(logs);

  const pieData = [
    { name: 'ALLOW', value: stats.allowed },
    { name: 'REJECT', value: stats.blocked },
    { name: 'FLOOR_UNREACHABLE', value: stats.floorUnreachable },
  ].filter((d) => d.value > 0);

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h1 className="page-title">Security Gateway</h1>
            <p className="page-subtitle">
              Real-time overview of QERIS gateway activity and baseline enforcement
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className={isLogsMocked ? 'mock-badge' : 'live-badge'}>
              {!gatewayOnline
                ? 'GATEWAY OFFLINE (SAMPLE DATA)'
                : isLogsMocked
                  ? 'LIVE GATEWAY (DEMO LOGS - SET ADMIN KEY)'
                  : 'LIVE GATEWAY & AUDIT LOGS'}
            </span>
            <div className={`gateway-banner ${gatewayOnline ? 'online' : 'offline'}`}>
              <span className={`status-dot ${gatewayOnline ? 'online' : 'offline'}`} />
              GATEWAY {gatewayOnline ? 'ONLINE' : 'OFFLINE'}
            </div>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* ── Gateway Operational State & Baseline Control Panel ───────────────── */}
        <div className="card section" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
          <div className="card-header">
            <span className="card-title">
              <Radio size={14} color="var(--accent-cyan)" />
              Gateway Operational State & Baseline Configuration
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                onClick={() => setShowAdminKeyBox(!showAdminKeyBox)}
                style={{
                  background: 'none',
                  border: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                  padding: '3px 8px',
                  borderRadius: 4,
                  fontSize: 11,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <Key size={11} />
                {adminKeyInput ? 'Admin Key Configured' : 'Set Admin Key'}
              </button>
              <button
                onClick={handleResetState}
                style={{
                  background: 'none',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: 'var(--red)',
                  padding: '3px 8px',
                  borderRadius: 4,
                  fontSize: 11,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <RefreshCw size={11} />
                Reset State
              </button>
            </div>
          </div>

          <div className="card-body">
            {showAdminKeyBox && (
              <div
                style={{
                  padding: '10px 14px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  marginBottom: 14,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Admin API Key:</span>
                <input
                  type="password"
                  placeholder="Enter QERIS_ADMIN_API_KEY..."
                  value={adminKeyInput}
                  onChange={(e) => setAdminKeyInput(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-base)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '4px 8px',
                    color: 'var(--text-primary)',
                    fontSize: 12,
                  }}
                />
                <button
                  onClick={handleAdminKeySave}
                  style={{
                    background: 'var(--accent-cyan)',
                    color: '#000',
                    border: 'none',
                    borderRadius: 4,
                    padding: '4px 10px',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Save
                </button>
              </div>
            )}

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: 16,
                marginBottom: 14,
              }}
            >
              <div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                  ACTIVE BASELINE
                </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-cyan)' }}>
                  {baselineConfig?.baseline_mode ?? gwStatus?.baseline_mode ?? 'full_gateway'}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 2 }}>
                  Frozen RFC 8785 execution model
                </span>
              </div>

              <div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                  ACTIVE POLICY VERSION
                </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--green)' }}>
                  v{gwStatus?.active_policy_version ?? 1} (Signed ML-DSA-65)
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 2 }}>
                  Monotonic anti-rollback verified
                </span>
              </div>

              <div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                  CLOUD FORWARDING & OUTAGE BUFFER
                </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                  Queue: {gwStatus?.cloud_queue_size ?? 0} | Dropped: {gwStatus?.cloud_dropped_count ?? 0}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginTop: 2 }}>
                  TLS verification enforced
                </span>
              </div>

              <div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                  SWITCH BASELINE MODE
                </span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <select
                    value={selectedBaseline}
                    onChange={(e) => setSelectedBaseline(e.target.value)}
                    style={{
                      background: 'var(--bg-base)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      color: 'var(--text-primary)',
                      padding: '4px 8px',
                      fontSize: 12,
                      flex: 1,
                    }}
                  >
                    {BASELINES.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.label}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={handleBaselineChange}
                    disabled={baselineUpdating}
                    style={{
                      background: 'var(--accent-cyan)',
                      color: '#000',
                      border: 'none',
                      borderRadius: 4,
                      padding: '4px 10px',
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: baselineUpdating ? 'not-allowed' : 'pointer',
                    }}
                  >
                    {baselineUpdating ? 'Applying...' : 'Apply'}
                  </button>
                </div>
              </div>
            </div>

            {statusMessage && (
              <div
                style={{
                  fontSize: 12,
                  padding: '6px 10px',
                  background: 'rgba(6, 182, 212, 0.08)',
                  border: '1px solid rgba(6, 182, 212, 0.2)',
                  borderRadius: 4,
                  color: 'var(--accent-cyan)',
                  marginTop: 8,
                }}
              >
                {statusMessage}
              </div>
            )}
          </div>
        </div>

        {/* Stat Cards */}
        <div className="stat-cards section">
          <StatCard
            label="Active Flows"
            value={stats.activeFlows}
            icon={Activity}
            colorClass="cyan"
          />
          <StatCard
            label="Allowed"
            value={stats.allowed}
            icon={CheckCircle}
            colorClass="green"
          />
          <StatCard
            label="Blocked"
            value={stats.blocked}
            icon={ShieldX}
            colorClass="red"
          />
          <StatCard
            label="Security Events"
            value={stats.securityEvents}
            icon={ShieldCheck}
            colorClass="amber"
          />
          <StatCard
            label="Floor Unreachable"
            value={stats.floorUnreachable}
            icon={AlertTriangle}
            colorClass="amber"
          />
        </div>

        {/* Middle row */}
        <div className="grid-2 section">
          {/* Security Floor Enforcement */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Lock size={14} color="var(--accent-cyan)" />
                Security Floor Enforcement
              </span>
              <span
                className="badge"
                style={{
                  background: 'rgba(16, 185, 129, 0.1)',
                  color: 'var(--green)',
                  borderColor: 'rgba(16, 185, 129, 0.2)',
                }}
              >
                ACTIVE
              </span>
            </div>
            <div className="card-body">
              <p
                style={{
                  fontSize: 12,
                  color: 'var(--text-muted)',
                  marginBottom: 20,
                  lineHeight: 1.6,
                }}
              >
                Every flow is evaluated against its minimum permitted security
                level before activation. The gateway is the sole authority.
              </p>

              {/* Hierarchy */}
              <div className="security-hierarchy">
                <div className="security-level-row">
                  <div className="security-level-block classical">CLASSICAL</div>
                  <span className="security-level-desc">Level 1 · Basic encryption</span>
                </div>
                <div className="security-arrow">
                  <ArrowDown size={14} />
                  <span style={{ fontSize: 10, marginLeft: 4, color: 'var(--text-muted)' }}>
                    stronger
                  </span>
                </div>
                <div className="security-level-row">
                  <div className="security-level-block hybrid">HYBRID</div>
                  <span className="security-level-desc">Level 2 · Classical + PQC</span>
                </div>
                <div className="security-arrow">
                  <ArrowDown size={14} />
                </div>
                <div className="security-level-row">
                  <div className="security-level-block pqc">PQC</div>
                  <span className="security-level-desc">Level 3 · Post-quantum only</span>
                </div>
              </div>

              <p
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  marginTop: 14,
                  borderTop: '1px solid var(--border)',
                  paddingTop: 12,
                }}
              >
                Minimum mode is flow-specific. Not all flows require PQC.
              </p>
            </div>
          </div>

          {/* Decision Distribution */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <GitBranch size={14} color="var(--accent-cyan)" />
                Decision Distribution
              </span>
            </div>
            <div className="card-body">
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={DECISION_COLORS[entry.name]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      fontSize: 12,
                      color: 'var(--text-primary)',
                    }}
                    formatter={(value, name) => [value, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
                {pieData.map((d) => (
                  <div
                    key={d.name}
                    style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}
                  >
                    <div
                      style={{
                        width: 10,
                        height: 10,
                        borderRadius: 2,
                        background: DECISION_COLORS[d.name],
                        flexShrink: 0,
                      }}
                    />
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {d.name}
                    </span>
                    <span
                      style={{ marginLeft: 'auto', color: 'var(--text-primary)', fontWeight: 600 }}
                    >
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Security Events row */}
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
              Latest Security Events
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
              {events.slice(0, 2).map((evt) => (
                <SecurityEventCard key={evt.id} event={evt} />
              ))}
            </div>
          </div>
        )}

        {/* Live Flow Monitor */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Activity size={14} color="var(--accent-cyan)" />
              Live Flow Monitor
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Click a row for details
            </span>
          </div>
          <FlowTable
            logs={logs.slice(0, 8)}
            onRowClick={(log) => setSelectedLog(log)}
          />
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
