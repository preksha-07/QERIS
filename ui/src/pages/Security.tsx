import React from 'react';
import { ShieldCheck, Lock, ArrowDown, CheckCircle, Info } from 'lucide-react';
import { failureRecoveryData } from '../data/mockData';

export const Security: React.FC = () => {
  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Security & Recovery</h1>
        <p className="page-subtitle">
          Security floor enforcement architecture and failure-classified recovery
        </p>
      </div>

      <div className="page-body">
        {/* Research contribution callout */}
        <div
          style={{
            background: 'rgba(6, 182, 212, 0.04)',
            border: '1px solid rgba(6, 182, 212, 0.15)',
            borderRadius: 8,
            padding: '14px 18px',
            marginBottom: 20,
          }}
        >
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-cyan)', marginBottom: 4 }}>
            Research Contribution
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            QERIS implements <strong style={{ color: 'var(--text-primary)' }}>Cause-Classified, Security-Floor-Bounded Recovery</strong> for
            post-quantum IoT handshakes. Every recovery action preserves the security floor
            defined by the gateway policy — the floor is never negotiated away.
          </div>
        </div>

        {/* Security Floor Section */}
        <div className="grid-2 section">
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
              {/* Decision flow */}
              <div
                style={{ display: 'flex', flexDirection: 'column', gap: 0, alignItems: 'flex-start' }}
              >
                {[
                  { label: 'Minimum security requirement', color: 'var(--accent-cyan)', bg: 'rgba(6,182,212,0.08)', border: 'rgba(6,182,212,0.2)' },
                  null,
                  { label: 'Requested security mode', color: 'var(--text-secondary)', bg: 'rgba(255,255,255,0.04)', border: 'var(--border)' },
                  null,
                  { label: 'Policy decision', color: 'var(--text-primary)', bg: 'rgba(255,255,255,0.03)', border: 'var(--border-accent)' },
                ].map((item, i) =>
                  item === null ? (
                    <div key={i} style={{ paddingLeft: 16, color: 'var(--text-muted)' }}>
                      <ArrowDown size={14} />
                    </div>
                  ) : (
                    <div
                      key={i}
                      style={{
                        padding: '8px 14px',
                        borderRadius: 6,
                        background: item.bg,
                        border: `1px solid ${item.border}`,
                        color: item.color,
                        fontSize: 12,
                        fontWeight: 500,
                        width: '100%',
                      }}
                    >
                      {item.label}
                    </div>
                  )
                )}
              </div>

              {/* Security hierarchy */}
              <div style={{ marginTop: 20 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 600 }}>
                  Security Hierarchy
                </div>
                <div className="security-hierarchy">
                  <div className="security-level-row">
                    <div className="security-level-block classical">CLASSICAL</div>
                    <span className="security-level-desc">Level 1</span>
                  </div>
                  <div className="security-arrow">
                    <ArrowDown size={14} />
                  </div>
                  <div className="security-level-row">
                    <div className="security-level-block hybrid">HYBRID</div>
                    <span className="security-level-desc">Level 2</span>
                  </div>
                  <div className="security-arrow">
                    <ArrowDown size={14} />
                  </div>
                  <div className="security-level-row">
                    <div className="security-level-block pqc">PQC</div>
                    <span className="security-level-desc">Level 3</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Cryptographic Stack */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <ShieldCheck size={14} color="var(--accent-cyan)" />
                Cryptographic Stack
              </span>
            </div>
            <div className="card-body">
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.6 }}>
                Components used by the QERIS S1 crypto layer. This dashboard
                displays system architecture only and does not perform cryptographic operations.
              </p>
              <div className="crypto-stack">
                {[
                  { name: 'ML-KEM-512', desc: 'Key Encapsulation (CRYSTALS-Kyber)' },
                  { name: 'HKDF-SHA256', desc: 'Session Key Derivation' },
                  { name: 'AES-256-GCM', desc: 'Authenticated Encryption' },
                  { name: 'ML-DSA', desc: 'Policy Signature Verification' },
                ].map((item) => (
                  <div className="crypto-item" key={item.name}>
                    <span className="crypto-item-name">{item.name}</span>
                    <span className="crypto-item-desc">{item.desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Failure Classification */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Info size={14} color="var(--accent-cyan)" />
              Failure Classification & Recovery
            </span>
          </div>
          <div className="card-body">
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
              QERIS classifies failures by cause before applying recovery. Each class has a
              bounded recovery action that preserves the security floor. Items marked{' '}
              <span className="mock-badge">PREPARED</span> are ready for S3 integration.
            </p>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
                gap: 12,
              }}
            >
              {failureRecoveryData.map((item) => (
                <div className="recovery-card" key={item.failureClass}>
                  <div className="recovery-header">
                    <span className="recovery-label">{item.label}</span>
                    {item.available ? (
                      <span className="live-badge">LIVE</span>
                    ) : (
                      <span className="mock-badge">PREPARED</span>
                    )}
                  </div>
                  <div className="recovery-rec">{item.recommendedRecovery}</div>
                  {item.securityFloorPreserved && (
                    <div className="recovery-floor">
                      <CheckCircle size={12} />
                      Security floor preserved
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
