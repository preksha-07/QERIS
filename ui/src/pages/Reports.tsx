import React, { useEffect, useState } from 'react';
import { FileSpreadsheet, BarChart3, Info, Layers, CheckCircle } from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus } from '../services/api';
import type { GatewayStatus } from '../types/qeris';

export const Reports: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);

  useEffect(() => {
    const init = async () => {
      const [gwStatus] = await Promise.all([
        getGatewayStatus(),
      ]);
      setStatus(gwStatus);
    };
    init();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        title="Reports & Research Evaluation"
        description="Experimental benchmarking framework and comparative evaluation metrics (Research Evaluation Phase)"
      />

      <div className="main-content">
        {/* Research Integrity & Honest Provenance Notice */}
        <div className="qeris-card" style={{
          marginBottom: 24,
          background: 'linear-gradient(180deg, #ffffff 0%, #f0f9ff 100%)',
          borderColor: 'var(--accent-cyan-light)',
        }}>
          <div style={{ display: 'flex', alignItems: 'start', gap: 14 }}>
            <div style={{
              width: 38,
              height: 38,
              borderRadius: 8,
              background: 'var(--accent-cyan-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-cyan)',
              flexShrink: 0,
            }}>
              <Info size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                Research Evaluation & Baseline Framework Notice
              </h3>
              <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.6 }}>
                In strict accordance with the <strong>Master Project Implementation + Research Blueprint</strong>, statistical benchmarks, latency distributions, and throughput figures are generated during formal <strong>Experimental Evaluation</strong>. To maintain scientific authenticity, no synthetic or fabricated test numbers are displayed.
              </p>
            </div>
          </div>
        </div>

        {/* Comparative Baseline Evaluation Matrix (B1 - B7) */}
        <div className="qeris-card" style={{ marginBottom: 24, padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 className="qeris-card-title">
                <BarChart3 size={16} color="var(--accent-cyan)" />
                Defined Evaluation Baselines (B0 - B7)
              </h2>
              <p className="qeris-card-subtitle">
                Architectural baselines frozen for comparative paper evaluation
              </p>
            </div>
            <span className="qeris-badge badge-allow mono">8 BASELINES SPECIFIED</span>
          </div>

          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Baseline ID</th>
                  <th>Configuration Name</th>
                  <th>Architectural Properties</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>B0 (PROPOSED)</td>
                  <td style={{ fontWeight: 600 }}>QERIS Proposed Gateway</td>
                  <td style={{ fontSize: 11.5 }}>Full sensitivity-aware policy engine + adaptive recovery controller.</td>
                  <td><span className="qeris-badge badge-allow">ACTIVE</span></td>
                </tr>
                <tr>
                  <td className="mono">B1</td>
                  <td>Static Classical</td>
                  <td style={{ fontSize: 11.5 }}>Pure ECDH / RSA classical cryptography; zero PQC migration.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B2</td>
                  <td>Static PQC</td>
                  <td style={{ fontSize: 11.5 }}>Forced pure ML-KEM-512 regardless of device resource constraints.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B3</td>
                  <td>Device Direct Cloud</td>
                  <td style={{ fontSize: 11.5 }}>Bypasses edge gateway; edge nodes connect directly to cloud TLS endpoint.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B4</td>
                  <td>Fixed Security Floor</td>
                  <td style={{ fontSize: 11.5 }}>Hardcoded non-adaptive security floor with no dynamic policy updates.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B5</td>
                  <td>Naive PQC Offload</td>
                  <td style={{ fontSize: 11.5 }}>Unconditional offload without sensitivity-guided floor verification.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B6</td>
                  <td>Non-Adaptive PQC</td>
                  <td style={{ fontSize: 11.5 }}>PQC without packet refragmentation or loss-adaptation recovery.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
                <tr>
                  <td className="mono">B7</td>
                  <td>Untrusted Metadata Baseline</td>
                  <td style={{ fontSize: 11.5 }}>Relies on unverified client-reported sensitivities to demonstrate risk.</td>
                  <td><span className="qeris-badge badge-neutral">FROZEN FOR EVALUATION</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Paper Target Specifications */}
        <div className="grid-2">
          <div className="qeris-card">
            <h3 className="qeris-card-title">
              <Layers size={16} color="var(--accent-blue)" />
              Experimental Evaluation Target Metrics
            </h3>
            <ul style={{ listStyle: 'none', padding: 0, marginTop: 12, display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12.5 }}>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle size={15} color="var(--status-allow)" />
                <strong>Handshake Latency CDF:</strong> Classical vs Hybrid vs ML-KEM-512 (ms)
              </li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle size={15} color="var(--status-allow)" />
                <strong>Packet Delivery Ratio:</strong> Lossy channels with and without adaptation
              </li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle size={15} color="var(--status-allow)" />
                <strong>Memory & Energy Footprint:</strong> Microcontroller RAM consumption (KB)
              </li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle size={15} color="var(--status-allow)" />
                <strong>Outage Durability:</strong> SQLite buffer retention under disconnected link
              </li>
            </ul>
          </div>

          <div className="qeris-card">
            <h3 className="qeris-card-title">
              <FileSpreadsheet size={16} color="var(--accent-cyan)" />
              Automated Artifact Exporter
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 8, lineHeight: 1.5 }}>
              The benchmarking suite generates publication-ready LaTeX tables, CSV raw datasets, and PDF distribution curves directly for the research manuscript.
            </p>
            <div style={{ marginTop: 16 }}>
              <button disabled className="btn btn-secondary" style={{ opacity: 0.6, cursor: 'not-allowed' }}>
                <FileSpreadsheet size={14} /> Export Dataset (Available in Formal Evaluation Phase)
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
