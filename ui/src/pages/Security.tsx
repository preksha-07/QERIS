import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  GitBranch,
  Layers,
} from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getSecurityEvents } from '../services/api';
import type { GatewayStatus, SecurityEvent, S3TaxonomyItem } from '../types/qeris';

const S3_TAXONOMY: S3TaxonomyItem[] = [
  {
    failureClass: 'SECURITY_FAILURE',
    title: 'Security Floor / Cryptographic Failure',
    description: 'Protocol violation, signature failure, or attempt to downgrade below authoritative floor.',
    action: 'DISCARD_AND_LOG',
    floorSafety: 'Strict Discard. No downgrade permitted under any condition.',
    provenance: 'Master Blueprint Invariant I1 & S3 Recovery Engine',
  },
  {
    failureClass: 'MTU_FRAGMENTATION',
    title: 'Network MTU Fragmentation Fault',
    description: 'PQC public key or ciphertext exceeds edge transport maximum transmission unit.',
    action: 'REFRAGMENT',
    floorSafety: 'Preserve PQC floor via application-level fragmentation without weakening crypto.',
    provenance: 'Master Blueprint S3 §4.2 Network Resilience',
  },
  {
    failureClass: 'LOSS_TIMEOUT',
    title: 'Packet Loss / Ingress Timeout',
    description: 'Lossy wireless link causing handshake expiration or dropped roundtrips.',
    action: 'EXTEND_TIMEOUT',
    floorSafety: 'Exponential backoff retry preserving identical cryptographic profile floor.',
    provenance: 'Master Blueprint S3 §4.3 Link Loss Adaptation',
  },
  {
    failureClass: 'CAUSE_UNKNOWN',
    title: 'Indeterminate / Unknown Ingress Cause',
    description: 'Failure signature does not match deterministic security or network telemetry.',
    action: 'OBSERVE_AND_WAIT',
    floorSafety: 'Safe fallback: quarantine anomaly observation window before retrying or dropping.',
    provenance: 'Master Blueprint DEC-3 / S3 Invariant I7 Verified',
  },
];

export const Security: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  const fetchData = async () => {
    const [gwStatus, secEvents] = await Promise.all([
      getGatewayStatus(),
      getSecurityEvents(),
    ]);
    setStatus(gwStatus);
    setEvents(secEvents);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Security & S3 Adaptive Recovery"
        description="Failure taxonomy classification, policy epoch transition safety, and live security events"
      />

      <div className="main-content">
        {/* S3 Research Contribution: Failure Taxonomy */}
        <div className="qeris-card" style={{ marginBottom: 24 }}>
          <div className="qeris-card-header">
            <div>
              <h2 className="qeris-card-title">
                <Layers size={16} color="var(--accent-cyan)" />
                S3 Adaptive Failure Taxonomy & Recovery Actions
              </h2>
              <p className="qeris-card-subtitle">
                Mathematical recovery mapping preserving security floor across all failure classes
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">S3 NOVEL CONTRIBUTION</span>
          </div>

          <div className="grid-2">
            {S3_TAXONOMY.map((item) => (
              <div
                key={item.failureClass}
                style={{
                  background: '#f8fafc',
                  border: '1px solid var(--border)',
                  borderRadius: 10,
                  padding: 16,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {item.failureClass}
                    </span>
                    <span className={`qeris-badge ${
                      item.action === 'DISCARD_AND_LOG'
                        ? 'badge-reject'
                        : item.action === 'OBSERVE_AND_WAIT'
                        ? 'badge-observe'
                        : 'badge-info'
                    }`}>
                      {item.action}
                    </span>
                  </div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>{item.title}</h4>
                  <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 10 }}>
                    {item.description}
                  </p>
                </div>

                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8, fontSize: 11 }}>
                  <div style={{ color: 'var(--text-muted)' }}>
                    <strong>Floor Guarantee:</strong> {item.floorSafety}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Policy Epoch Safety (DEC-4 / Invariant I8) Visual Workflow */}
        <div className="qeris-card" style={{ marginBottom: 24 }}>
          <div className="qeris-card-header">
            <div>
              <h3 className="qeris-card-title">
                <GitBranch size={16} color="var(--status-allow)" />
                Policy Epoch Transition Safety (DEC-4 / Invariant I8)
              </h3>
              <p className="qeris-card-subtitle">
                Deterministic session lifecycle handling during mid-flight policy upgrades
              </p>
            </div>
            <span className="qeris-badge badge-allow mono">VERIFIED IN RUNTIME</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            <div style={{ background: '#ecfdf5', border: '1px solid #a7f3d0', borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#047857', marginBottom: 4 }}>
                1. COMPLIANT_REBIND
              </div>
              <p style={{ fontSize: 11, color: '#065f46' }}>
                If an active session satisfies or exceeds the newly published policy floor, it is seamlessly rebound to the new policy epoch without dropping traffic.
              </p>
            </div>

            <div style={{ background: '#fffbeb', border: '1px solid #fde68a', borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#b45309', marginBottom: 4 }}>
                2. INCOMPATIBLE_RESTART
              </div>
              <p style={{ fontSize: 11, color: '#92400e' }}>
                If a device can support the new floor but the existing session is lower, the gateway securely terminates the session and triggers renegotiation.
              </p>
            </div>

            <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#b91c1c', marginBottom: 4 }}>
                3. IMPOSSIBLE_QUARANTINE
              </div>
              <p style={{ fontSize: 11, color: '#991b1b' }}>
                If a device cannot physically reach the new floor (hardware deficit), traffic is terminated and the node is quarantined. Zero silent downgrade.
              </p>
            </div>
          </div>
        </div>

        {/* Live Security Events Table */}
        <div className="qeris-card" style={{ padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 className="qeris-card-title">
                <ShieldAlert size={16} color="var(--status-reject)" />
                Security Failure & Enforcement Event Feed
              </h3>
              <p className="qeris-card-subtitle">
                Filtered real-time audit records showing blocked downgrade attempts
              </p>
            </div>
            <span className="qeris-badge badge-reject mono">{events.length} BLOCKED EVENTS</span>
          </div>

          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Device ID</th>
                  <th>Flow ID</th>
                  <th>Required Floor</th>
                  <th>Attempted Mode</th>
                  <th>Gateway Enforcement</th>
                  <th>Enforcement Reason</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                      No active security violations recorded.
                    </td>
                  </tr>
                ) : (
                  events.map((evt, idx) => (
                    <tr key={evt.id || idx}>
                      <td className="mono" style={{ fontSize: 10.5 }}>
                        {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'Recent'}
                      </td>
                      <td className="mono" style={{ fontWeight: 600 }}>{evt.device_id}</td>
                      <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{evt.flow_id}</td>
                      <td>
                        <span className="qeris-badge badge-allow mono" style={{ fontSize: 10 }}>
                          {evt.required_mode ?? 'HYBRID'}
                        </span>
                      </td>
                      <td>
                        <span className="qeris-badge badge-reject mono" style={{ fontSize: 10 }}>
                          {evt.requested_mode}
                        </span>
                      </td>
                      <td>
                        <span className="qeris-badge badge-reject">
                          {evt.decision}
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                        {evt.reason}
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
