import React, { useEffect, useState } from 'react';
import { FileText, ArrowUp } from 'lucide-react';
import { getPolicies } from '../services/api';
import type { Policy } from '../types/qeris';
import { SECURITY_LEVEL } from '../types/qeris';
import { ModeBadge, SensitivityBadge } from '../components/SecurityBadge';

export const Policies: React.FC = () => {
  const [policies, setPolicies] = useState<Policy[]>([]);

  useEffect(() => {
    getPolicies().then(({ data }) => setPolicies(data));
  }, []);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Policies</h1>
        <p className="page-subtitle">
          Active security floor policies enforced by the QERIS gateway
        </p>
      </div>

      <div className="page-body">
        <div
          style={{
            background: 'rgba(6, 182, 212, 0.04)',
            border: '1px solid rgba(6, 182, 212, 0.15)',
            borderRadius: 8,
            padding: '12px 16px',
            fontSize: 12,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.6,
          }}
        >
          <strong style={{ color: 'var(--accent-cyan)' }}>Read-only view.</strong>{' '}
          This interface visualizes the gateway's active policy. The frontend cannot
          override or modify security policy — the gateway remains the sole authority.
        </div>

        {/* Policy Cards */}
        <div className="grid-2 section">
          {policies.map((policy) => {
            const level = SECURITY_LEVEL[policy.minimum_mode];
            return (
              <div className="policy-card" key={policy.flow_id}>
                {/* Floor bar */}
                <div className="floor-bar" style={{ marginBottom: 12 }}>
                  <div
                    className={`floor-segment ${
                      level >= 1 ? 'filled-classical' : 'empty'
                    }`}
                  />
                  <div
                    className={`floor-segment ${
                      level >= 2 ? 'filled-hybrid' : 'empty'
                    }`}
                  />
                  <div
                    className={`floor-segment ${
                      level >= 3 ? 'filled-pqc' : 'empty'
                    }`}
                  />
                </div>

                <div className="policy-flow-id">{policy.flow_id}</div>

                <div className="policy-row">
                  <span className="policy-key">Sensitivity</span>
                  <SensitivityBadge sensitivity={policy.sensitivity} />
                </div>
                <div className="policy-row">
                  <span className="policy-key">Minimum Mode (Floor)</span>
                  <ModeBadge mode={policy.minimum_mode} />
                </div>
                <div className="policy-row">
                  <span className="policy-key">Policy Version</span>
                  <span className="policy-val mono">v{policy.policy_version}</span>
                </div>
                <div className="policy-row">
                  <span className="policy-key">Authority</span>
                  <span className="policy-val mono">{policy.authority_id}</span>
                </div>

                {/* Floor explanation */}
                <div
                  style={{
                    marginTop: 10,
                    padding: '8px 10px',
                    background: 'var(--bg-base)',
                    borderRadius: 5,
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 6,
                  }}
                >
                  <ArrowUp size={11} color="var(--accent-cyan)" style={{ marginTop: 1, flexShrink: 0 }} />
                  <span>
                    Requests below <strong style={{ color: 'var(--text-secondary)' }}>{policy.minimum_mode}</strong> will
                    be rejected. Requests at or above the floor are evaluated for
                    device capability.
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Table view */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <FileText size={14} color="var(--accent-cyan)" />
              Policy Summary Table
            </span>
            <span className="mock-badge">DEMO DATA</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Sensitivity</th>
                  <th>Min Mode (Floor)</th>
                  <th>Policy Version</th>
                  <th>Authority</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.flow_id}>
                    <td className="mono">{policy.flow_id}</td>
                    <td>
                      <SensitivityBadge sensitivity={policy.sensitivity} />
                    </td>
                    <td>
                      <ModeBadge mode={policy.minimum_mode} />
                    </td>
                    <td className="mono">v{policy.policy_version}</td>
                    <td className="mono">{policy.authority_id}</td>
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
