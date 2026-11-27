import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Layers,
  ArrowRight,
  Server,
  Cloud,
} from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getAuditLogs } from '../services/api';
import type { GatewayStatus, AuditLog } from '../types/qeris';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

export const Overview: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [logs, setLogs] = useState<AuditLog[]>([]);

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
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  // Compute decisions distribution
  const allowCount = logs.filter(l => l.decision === 'ALLOW').length;
  const rejectCount = logs.filter(l => l.decision === 'REJECT').length;
  const floorUnreachableCount = logs.filter(l => l.decision === 'FLOOR_UNREACHABLE').length;
  const totalDecisions = logs.length || 1;

  const chartData = [
    { name: 'ALLOW', value: allowCount, color: 'var(--status-allow)' },
    { name: 'REJECT', value: rejectCount, color: 'var(--status-reject)' },
    { name: 'FLOOR_UNREACHABLE', value: floorUnreachableCount, color: 'var(--status-unreachable)' },
  ].filter(d => d.value > 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Overview & Gateway Control"
        description="Sensitivity-Aware & Failure-Resilient Post-Quantum Gateway Orchestration Center"
      />

      <div className="main-content">
        {/* Top KPI Metrics Banner */}
        <div className="grid-4" style={{ marginBottom: 24 }}>
          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Active Protected Flows</span>
              <Activity size={18} color="var(--accent-cyan)" />
            </div>
            <div className="kpi-value">{status?.verified_flows_count ?? 4}</div>
            <div className="kpi-footer">
              <span className="qeris-badge badge-allow" style={{ padding: '2px 6px' }}>100% Policy Bound</span>
              <span>Root authority certified</span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Allowed Ingress</span>
              <ShieldCheck size={18} color="var(--status-allow)" />
            </div>
            <div className="kpi-value" style={{ color: 'var(--status-allow)' }}>
              {allowCount}
            </div>
            <div className="kpi-footer">
              <span className="mono">{((allowCount / totalDecisions) * 100).toFixed(0)}%</span>
              <span>Compliant with security floor</span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Downgrades Rejected</span>
              <ShieldAlert size={18} color="var(--status-reject)" />
            </div>
            <div className="kpi-value" style={{ color: 'var(--status-reject)' }}>
              {rejectCount}
            </div>
            <div className="kpi-footer">
              <span className="qeris-badge badge-reject" style={{ padding: '2px 6px' }}>I1 Non-Bypassable</span>
              <span>Floor violations blocked</span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Floor Unreachable</span>
              <AlertTriangle size={18} color="var(--status-unreachable)" />
            </div>
            <div className="kpi-value" style={{ color: 'var(--status-unreachable)' }}>
              {floorUnreachableCount}
            </div>
            <div className="kpi-footer">
              <span className="qeris-badge badge-unreachable" style={{ padding: '2px 6px' }}>Adaptive Hook Active</span>
              <span>Device capability deficient</span>
            </div>
          </div>
        </div>

        {/* Central End-to-End Architectural Dataflow Visualizer */}
        <div className="qeris-card" style={{ marginBottom: 24 }}>
          <div className="qeris-card-header">
            <div>
              <h2 className="qeris-card-title">
                <Layers size={17} color="var(--accent-cyan)" />
                End-to-End Quantum-Safe Gateway Architecture
              </h2>
              <p className="qeris-card-subtitle">
                Authoritative Master Blueprint Specification: Dual-leg decoupled security architecture
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">INVARIANTS I1 - I8 ENFORCED</span>
          </div>

          <div className="arch-flow-diagram">
            {/* Device Layer */}
            <div className="arch-node">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 8 }}>
                <Cpu size={18} color="var(--accent-cyan)" />
                <strong style={{ fontSize: 13 }}>Edge IoT Devices</strong>
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
                Heterogeneous profiles (ESP32, Nordic, Linux Edge)
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="qeris-badge badge-neutral mono" style={{ fontSize: 10, justifyContent: 'center' }}>
                  Device Leg: CoAP / TCP / Raw
                </span>
                <span className="qeris-badge badge-info mono" style={{ fontSize: 10, justifyContent: 'center' }}>
                  PQ Crypto: ML-KEM-512 / X25519
                </span>
              </div>
            </div>

            <div className="arch-connector">
              <ArrowRight size={22} />
              <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--text-muted)' }}>INGRESS</span>
            </div>

            {/* QERIS Security Gateway */}
            <div className="arch-node" style={{
              flex: 1.4,
              background: 'linear-gradient(180deg, #ffffff 0%, #f0f9ff 100%)',
              borderColor: 'var(--accent-cyan-light)',
              boxShadow: '0 4px 12px rgba(2, 132, 199, 0.08)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 6 }}>
                <Server size={18} color="var(--accent-cyan)" />
                <strong style={{ fontSize: 14, color: 'var(--accent-cyan)' }}>QERIS Security Gateway</strong>
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 10 }}>
                Authoritative Policy Engine + Adaptive Recovery Controller
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6, textAlign: 'left' }}>
                <div style={{ background: '#fff', padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)' }}>POLICY EVALUATION</div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--status-allow)' }}>DEC-1 to DEC-4 Check</div>
                </div>
                <div style={{ background: '#fff', padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)' }}>ADAPTIVE RECOVERY HOOK</div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--status-observe)' }}>Failure Classification</div>
                </div>
              </div>
            </div>

            <div className="arch-connector">
              <ArrowRight size={22} />
              <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--text-muted)' }}>MUTUAL TLS</span>
            </div>

            {/* Cloud Storage / Analytics */}
            <div className="arch-node">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 8 }}>
                <Cloud size={18} color="var(--accent-blue)" />
                <strong style={{ fontSize: 13 }}>Enterprise Cloud</strong>
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
                Telemetry Ingest, Aggregation & Long-term Store
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="qeris-badge badge-neutral mono" style={{ fontSize: 10, justifyContent: 'center' }}>
                  Cloud Leg: HTTPS / mTLS
                </span>
                <span className="qeris-badge badge-info mono" style={{ fontSize: 10, justifyContent: 'center' }}>
                  Buffered SQLite Store
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Decisions Stream and Chart */}
        <div className="grid-2">
          {/* Decision Breakdown Donut */}
          <div className="qeris-card">
            <div className="qeris-card-header">
              <h3 className="qeris-card-title">
                <ShieldCheck size={16} color="var(--accent-cyan)" />
                Ingress Decision Distribution
              </h3>
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {logs.length} evaluated flows
              </span>
            </div>

            <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={85}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No evaluation data available</div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-around', paddingTop: 12, borderTop: '1px solid var(--border)' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>ALLOW</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-allow)' }}>{allowCount}</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>REJECT</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-reject)' }}>{rejectCount}</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>UNREACHABLE</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-unreachable)' }}>{floorUnreachableCount}</div>
              </div>
            </div>
          </div>

          {/* Recent Audit Log Stream */}
          <div className="qeris-card">
            <div className="qeris-card-header">
              <h3 className="qeris-card-title">
                <Activity size={16} color="var(--accent-cyan)" />
                Gateway Ingress Stream
              </h3>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <span className="qeris-badge badge-neutral mono" style={{ fontSize: 9.5 }}>DEMO AUDIT LOG</span>
                <span className="qeris-badge badge-neutral" style={{ fontSize: 10 }}>Ingress Feed</span>
              </div>
            </div>

            <div style={{ maxHeight: 270, overflowY: 'auto' }}>
              {logs.length === 0 ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
                  Awaiting gateway flow checks...
                </div>
              ) : (
                <table className="qeris-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Flow ID</th>
                      <th>Requested</th>
                      <th>Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.slice(0, 6).map((log, idx) => (
                      <tr key={log.id || idx}>
                        <td className="mono" style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Recent'}
                        </td>
                        <td className="mono" style={{ fontWeight: 600 }}>{log.flow_id}</td>
                        <td>
                          <span className="qeris-badge badge-neutral mono" style={{ fontSize: 10 }}>
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
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
