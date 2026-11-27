import React, { useEffect, useState } from 'react';
import { Cloud, Database, HardDrive } from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getCloudStats, getCloudRecords } from '../services/api';
import type { GatewayStatus, CloudStats, CloudRecord } from '../types/qeris';

export const CloudMonitor: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [stats, setStats] = useState<CloudStats | null>(null);
  const [records, setRecords] = useState<CloudRecord[]>([]);

  const fetchData = async () => {
    const [gwStatus, cloudStats, cloudRecords] = await Promise.all([
      getGatewayStatus(),
      getCloudStats(),
      getCloudRecords(),
    ]);
    setStatus(gwStatus);
    setStats(cloudStats);
    setRecords(cloudRecords);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Cloud & Telemetry Forwarding"
        description="S2 Cloud Forwarder monitor, mutual TLS egress channel, and SQLite telemetry store"
      />

      <div className="main-content">
        {/* Architecture Isolation Banner */}
        <div className="qeris-card" style={{ marginBottom: 24 }}>
          <div className="qeris-card-header">
            <div>
              <h2 className="qeris-card-title">
                <Cloud size={16} color="var(--accent-blue)" />
                Dual-Leg Network Isolation Architecture
              </h2>
              <p className="qeris-card-subtitle">
                Clear cryptographic boundary separation between Device-to-Gateway and Gateway-to-Cloud legs
              </p>
            </div>
            <span className="qeris-badge badge-info mono">DECOUPLED TRANSPORT</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            <div style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span className="qeris-badge badge-neutral mono">LEG 1: DEVICE TO GATEWAY</span>
              </div>
              <h4 style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>Post-Quantum Edge Channel</h4>
              <p style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                Protected with ML-KEM-512 / X25519 hybrid KEM and AES-256-GCM. Designed for constrained edge nodes with S3 adaptive re-fragmentation.
              </p>
            </div>

            <div style={{ background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 10, padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span className="qeris-badge badge-info mono">LEG 2: GATEWAY TO CLOUD</span>
              </div>
              <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-blue)', marginBottom: 4 }}>
                Enterprise Mutual TLS Egress
              </h4>
              <p style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                Mutual TLS (port 8001) with local SQLite outage buffer. Resilient forwarder tolerates cloud network dropouts without data loss.
              </p>
            </div>
          </div>
        </div>

        {/* Telemetry Buffer & Forwarding Metrics */}
        <div className="grid-3" style={{ marginBottom: 24 }}>
          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Cloud Forwarder State</span>
              <Cloud size={18} color="var(--accent-cyan)" />
            </div>
            <div className="kpi-value" style={{ fontSize: 20 }}>
              {stats?.cloud_healthy ? 'ONLINE / mTLS' : 'BUFFERED / OFFLINE'}
            </div>
            <div className="kpi-footer">
              <span className={`pulse-dot ${stats?.cloud_healthy ? 'online' : 'offline'}`} />
              <span>Target: https://localhost:8001</span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Local Outage Buffer</span>
              <HardDrive size={18} color="var(--accent-blue)" />
            </div>
            <div className="kpi-value">
              {status?.cloud_queue_size ?? stats?.outage_buffer_size ?? 0}
            </div>
            <div className="kpi-footer">
              <span className="mono">0 Dropped Packets</span>
              <span>(Durable disk queue)</span>
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span className="kpi-label">Total Delivered Telemetry</span>
              <Database size={18} color="var(--status-allow)" />
            </div>
            <div className="kpi-value" style={{ color: 'var(--status-allow)' }}>
              {stats?.total_records ?? 0}
            </div>
            <div className="kpi-footer">
              <span className="qeris-badge badge-allow">Ingress Verified</span>
              <span>Stored in cloud DB</span>
            </div>
          </div>
        </div>

        {/* Stored Cloud Telemetry Table */}
        <div className="qeris-card" style={{ padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 className="qeris-card-title">
                <Database size={16} color="var(--accent-cyan)" />
                Cloud Ingress Telemetry Store (Live Stream)
              </h3>
              <p className="qeris-card-subtitle">
                Authoritative records confirmed delivered to cloud endpoint
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">{records.length} STORED RECORDS</span>
          </div>

          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Device Identifier</th>
                  <th>Flow ID</th>
                  <th>Sensitivity</th>
                  <th>Security Profile</th>
                  <th>Policy Digest</th>
                  <th>Gateway Decision</th>
                </tr>
              </thead>
              <tbody>
                {records.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                      No telemetry records stored in cloud database yet.
                    </td>
                  </tr>
                ) : (
                  records.map((rec, idx) => (
                    <tr key={rec.event_id || idx}>
                      <td className="mono" style={{ fontSize: 11 }}>{rec.event_id}</td>
                      <td className="mono" style={{ fontWeight: 600 }}>{rec.device_id}</td>
                      <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{rec.flow_id}</td>
                      <td>
                        <span className="qeris-badge badge-neutral">{rec.sensitivity}</span>
                      </td>
                      <td className="mono" style={{ fontSize: 10.5 }}>{rec.security_profile}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {rec.policy_digest?.slice(0, 16) || 'verified'}...
                      </td>
                      <td>
                        <span className="qeris-badge badge-allow">{rec.gateway_decision}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
