import React, { useState, useEffect } from 'react';
import {
  Terminal,
  Play,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Layers,
} from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getDevices, getPolicies, executeCryptoDemo } from '../services/api';
import type { GatewayStatus, Device, Policy, TransmissionResult, SecurityMode, Sensitivity } from '../types/qeris';

export const Playground: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);

  // Form inputs
  const [selectedDevice, setSelectedDevice] = useState<string>('device-linux-edge-01');
  const [selectedFlow, setSelectedFlow] = useState<string>('flow-telemetry-critical');
  const [requestedMode, setRequestedMode] = useState<SecurityMode>('PQC');
  const [reportedSensitivity, setReportedSensitivity] = useState<Sensitivity>('CRITICAL');
  const [testPayload, setTestPayload] = useState<string>('{"sensor_reading": 42.8, "alert": "HIGH_VOLTAGE"}');

  // Evaluation states
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [result, setResult] = useState<TransmissionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const init = async () => {
      const [gwStatus, devList, polList] = await Promise.all([
        getGatewayStatus(),
        getDevices(),
        getPolicies(),
      ]);
      setStatus(gwStatus);
      setDevices(devList);
      setPolicies(polList);
      if (devList.length > 0) setSelectedDevice(devList[0].device_id);
      if (polList.length > 0) setSelectedFlow(polList[0].flow_id);
    };
    init();
  }, []);

  const handleExecute = async () => {
    setEvaluating(true);
    setError(null);
    setResult(null);

    try {
      const transmission = await executeCryptoDemo(
        selectedDevice,
        selectedFlow,
        requestedMode,
        testPayload
      );
      setResult(transmission);
    } catch (err: any) {
      setError(err?.message || 'Error communicating with QERIS Gateway');
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        title="Interactive Gateway Playground"
        description="Simulate edge node requests, test security floor enforcement, and execute real cryptographic primitives"
      />

      <div className="main-content">
        <div className="grid-2" style={{ alignItems: 'start', marginBottom: 24 }}>
          {/* Input Configuration Card */}
          <div className="qeris-card">
            <div className="qeris-card-header">
              <h2 className="qeris-card-title">
                <Terminal size={16} color="var(--accent-cyan)" />
                Flow Ingress Simulator
              </h2>
              <span className="qeris-badge badge-neutral mono">INTERACTIVE DEMO</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                  SELECT INGRESS DEVICE
                </label>
                <select
                  value={selectedDevice}
                  onChange={(e) => setSelectedDevice(e.target.value)}
                  className="qeris-select"
                  style={{ marginTop: 4 }}
                >
                  {devices.map(d => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.device_id} ({d.supported_modes.join(', ')})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                  TARGET FLOW IDENTIFIER
                </label>
                <select
                  value={selectedFlow}
                  onChange={(e) => setSelectedFlow(e.target.value)}
                  className="qeris-select"
                  style={{ marginTop: 4 }}
                >
                  {policies.map(p => (
                    <option key={p.flow_id} value={p.flow_id}>
                      {p.flow_id} (Floor: {p.minimum_mode}, Sens: {p.sensitivity})
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                    REQUESTED SECURITY MODE
                  </label>
                  <select
                    value={requestedMode}
                    onChange={(e) => setRequestedMode(e.target.value as SecurityMode)}
                    className="qeris-select"
                    style={{ marginTop: 4 }}
                  >
                    <option value="CLASSICAL">CLASSICAL (ECDH)</option>
                    <option value="HYBRID">HYBRID (X25519 + ML-KEM)</option>
                    <option value="PQC">PQC (Pure ML-KEM-512)</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                    UNTRUSTED DEVICE SENSITIVITY
                  </label>
                  <select
                    value={reportedSensitivity}
                    onChange={(e) => setReportedSensitivity(e.target.value as Sensitivity)}
                    className="qeris-select"
                    style={{ marginTop: 4 }}
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                  PAYLOAD / TELEMETRY MESSAGE
                </label>
                <textarea
                  rows={3}
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  className="qeris-input mono"
                  style={{ marginTop: 4, resize: 'vertical' }}
                />
              </div>

              <button
                onClick={handleExecute}
                disabled={evaluating}
                className="btn btn-primary"
                style={{ marginTop: 6, width: '100%' }}
              >
                {evaluating ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" /> Evaluating Gateway Policy...
                  </>
                ) : (
                  <>
                    <Play size={14} /> Submit Flow & Test Decision
                  </>
                )}
              </button>

              {error && (
                <div style={{ padding: 10, background: 'var(--status-reject-bg)', color: 'var(--status-reject)', borderRadius: 8, fontSize: 12 }}>
                  {error}
                </div>
              )}
            </div>
          </div>

          {/* Decision Outcome & Cryptographic Verification Card */}
          <div className="qeris-card">
            <div className="qeris-card-header">
              <h2 className="qeris-card-title">
                <ShieldCheck size={16} color="var(--accent-cyan)" />
                Gateway Decision & Crypto Outcome
              </h2>
              <span className="qeris-badge badge-neutral mono">EVALUATION RESULT</span>
            </div>

            {!result ? (
              <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
                <Layers size={36} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
                <p style={{ fontWeight: 600 }}>Awaiting Flow Ingress Submission</p>
                <p style={{ fontSize: 12, marginTop: 4 }}>
                  Configure device parameters on the left and click Submit Flow.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Decision Banner */}
                <div style={{
                  padding: 14,
                  borderRadius: 10,
                  border: '1px solid',
                  background:
                    result.gateway.decision === 'ALLOW'
                      ? 'var(--status-allow-bg)'
                      : result.gateway.decision === 'REJECT'
                      ? 'var(--status-reject-bg)'
                      : 'var(--status-unreachable-bg)',
                  borderColor:
                    result.gateway.decision === 'ALLOW'
                      ? 'var(--status-allow-border)'
                      : result.gateway.decision === 'REJECT'
                      ? 'var(--status-reject-border)'
                      : 'var(--status-unreachable-border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {result.gateway.decision === 'ALLOW' ? (
                        <ShieldCheck size={22} color="var(--status-allow)" />
                      ) : result.gateway.decision === 'REJECT' ? (
                        <ShieldAlert size={22} color="var(--status-reject)" />
                      ) : (
                        <AlertTriangle size={22} color="var(--status-unreachable)" />
                      )}
                      <div>
                        <div style={{
                          fontWeight: 800,
                          fontSize: 16,
                          color:
                            result.gateway.decision === 'ALLOW'
                              ? 'var(--status-allow)'
                              : result.gateway.decision === 'REJECT'
                              ? 'var(--status-reject)'
                              : 'var(--status-unreachable)',
                        }}>
                          GATEWAY DECISION: {result.gateway.decision}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                          {result.gateway.reason}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Recovery Verdict & Floor Comparison */}
                <div style={{ background: '#f8fafc', padding: 12, borderRadius: 8, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Blueprint Invariant Checks
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, marginTop: 6 }}>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Authority Floor:</span>{' '}
                      <strong className="mono">{result.gateway.minimum_mode ?? 'NONE'}</strong>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Requested:</span>{' '}
                      <strong className="mono">{result.gateway.requested_mode}</strong>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Recovery Verdict:</span>{' '}
                      <span className="mono" style={{ color: 'var(--status-observe)', fontWeight: 600 }}>
                        {result.gateway.s3_verdict || 'NOMINAL'}
                      </span>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Cloud Ingress:</span>{' '}
                      <span className="mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                        {result.cloud_delivery || 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Cryptographic Execution Panel */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4 }}>
                    POST-QUANTUM CRYPTOGRAPHIC DATA-PATH
                  </div>
                  {result.crypto ? (
                    <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: 12 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--status-allow)' }}>
                          {result.crypto.algorithm}
                        </span>
                        <span className="qeris-badge badge-allow">VERIFIED DECRYPT</span>
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Ciphertext (Hex):</div>
                      <div className="mono" style={{ fontSize: 10, wordBreak: 'break-all', background: '#fff', padding: 6, borderRadius: 4, border: '1px solid #dcfce7' }}>
                        {result.crypto.ciphertext_hex || 'Generated via AES-256-GCM'}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', margin: '6px 0 2px' }}>Decrypted Plaintext:</div>
                      <div className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {result.crypto.decrypted_message}
                      </div>
                    </div>
                  ) : (
                    <div style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: 8, padding: 12, color: 'var(--text-muted)', fontSize: 11 }}>
                      {result.gateway.decision === 'ALLOW'
                        ? 'Simulated transmission complete (Crypto demo endpoint response recorded).'
                        : 'Transmission blocked at gateway ingress. Cryptographic session denied to preserve security floor.'}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
