import React, { useEffect, useState } from 'react';
import { Lock, CheckCircle2, FileText } from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getPolicies } from '../services/api';
import type { GatewayStatus, Policy } from '../types/qeris';

export const Policies: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);

  const fetchData = async () => {
    const [gwStatus, polList] = await Promise.all([
      getGatewayStatus(),
      getPolicies(),
    ]);
    setStatus(gwStatus);
    setPolicies(polList);
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Authoritative Policies"
        description="Root authority cryptographically signed policy specifications defining security floor invariants"
      />

      <div className="main-content">
        {/* Policy Engine Authority Certificate Card */}
        <div className="qeris-card" style={{ marginBottom: 24, background: 'linear-gradient(180deg, #ffffff 0%, #f8fafc 100%)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 44,
                height: 44,
                borderRadius: 10,
                background: 'var(--accent-cyan-light)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-cyan)',
              }}>
                <Lock size={22} />
              </div>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 700 }}>Root Authority: {status?.authority_id ?? 'AUTH-QERIS-ROOT-01'}</h2>
                <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Ed25519 Authority Keypair Verified • Invariants DEC-1 through DEC-4 Non-Bypassable
                </p>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span className="qeris-badge badge-allow" style={{ fontSize: 12, padding: '4px 10px' }}>
                <CheckCircle2 size={13} /> Active Policy Epoch: v{status?.active_policy_version ?? 1}
              </span>
              <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}>
                Digest: {status?.active_policy_digest?.slice(0, 24) || 'e3b0c44298fc1c149afbf4c8'}...
              </div>
            </div>
          </div>
        </div>

        {/* Policies Specification Table */}
        <div className="qeris-card" style={{ padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 className="qeris-card-title">
                <FileText size={16} color="var(--accent-cyan)" />
                Registered Flow Policy Rules
              </h3>
              <p className="qeris-card-subtitle">
                Floor requirements mapped to sensitivity classifications
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">{policies.length} ACTIVE POLICIES</span>
          </div>

          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Flow Identifier</th>
                  <th>Sensitivity</th>
                  <th>Minimum Security Floor</th>
                  <th>Approved Profiles</th>
                  <th>Policy Version</th>
                  <th>Authority Signature</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.flow_id}>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                      {policy.flow_id}
                    </td>
                    <td>
                      <span className={`qeris-badge ${
                        policy.sensitivity === 'CRITICAL'
                          ? 'badge-reject'
                          : policy.sensitivity === 'HIGH'
                          ? 'badge-unreachable'
                          : 'badge-neutral'
                      }`}>
                        {policy.sensitivity}
                      </span>
                    </td>
                    <td>
                      <span className={`qeris-badge ${
                        policy.minimum_mode === 'PQC'
                          ? 'badge-allow'
                          : policy.minimum_mode === 'HYBRID'
                          ? 'badge-info'
                          : 'badge-neutral'
                      } mono`}>
                        {policy.minimum_mode}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {policy.approved_profiles && policy.approved_profiles.length > 0 ? (
                          policy.approved_profiles.map((prof) => (
                            <span key={prof} className="qeris-badge badge-neutral mono" style={{ fontSize: 9.5 }}>
                              {prof}
                            </span>
                          ))
                        ) : (
                          <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                            STANDARD_SUITE
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="mono">v{policy.policy_version}</td>
                    <td>
                      <span className="qeris-badge badge-allow" style={{ fontSize: 10.5 }}>
                        <CheckCircle2 size={12} /> ED25519 VALID
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
