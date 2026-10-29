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
} from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { SecurityEventCard } from '../components/SecurityEvent';
import { FlowTable } from '../components/FlowTable';
import { FlowDetailModal } from '../components/FlowDetailModal';
import { getAuditLogs, getSecurityEvents } from '../services/api';
import { computeStats } from '../data/mockData';
import type { AuditLog, SecurityEvent } from '../types/qeris';
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

export const Dashboard: React.FC<DashboardProps> = ({ gatewayOnline }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  useEffect(() => {
    getAuditLogs().then(({ data }) => setLogs(data));
    getSecurityEvents().then(({ data }) => setEvents(data));
  }, []);

  const stats = computeStats(logs);

  // Pie chart data
  const pieData = [
    { name: 'ALLOW', value: stats.allowed },
    { name: 'REJECT', value: stats.blocked },
    { name: 'FLOOR_UNREACHABLE', value: stats.floorUnreachable },
  ].filter((d) => d.value > 0);

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 className="page-title">Security Gateway</h1>
            <p className="page-subtitle">
              Real-time overview of QERIS gateway activity
            </p>
          </div>
          <div
            className={`gateway-banner ${gatewayOnline ? 'online' : 'offline'}`}
          >
            <span
              className={`status-dot ${gatewayOnline ? 'online' : 'offline'}`}
            />
            GATEWAY {gatewayOnline ? 'ONLINE' : 'OFFLINE'}
          </div>
        </div>
      </div>

      <div className="page-body">
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
