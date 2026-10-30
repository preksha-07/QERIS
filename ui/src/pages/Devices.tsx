import React, { useEffect, useState } from 'react';
import { Cpu, AlertTriangle, Radio, Lock, Unlock } from 'lucide-react';
import { DeviceTable } from '../components/DeviceTable';
import { getDevices, simulateTransmission } from '../services/api';
import { mockPolicies, mockDevices } from '../data/mockData';
import type { Device, SecurityMode, TransmissionResult } from '../types/qeris';
import { SECURITY_LEVEL } from '../types/qeris';
import {
  DecisionBadge,
  ModeBadge,
  SensitivityBadge,
} from '../components/SecurityBadge';

const SECURITY_MODES: SecurityMode[] = ['CLASSICAL', 'HYBRID', 'PQC'];

// ─── select style shared across all three dropdowns ──────────────────────────
const SELECT_STYLE: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text-primary)',
  fontSize: 13,
  padding: '7px 10px',
  cursor: 'pointer',
  outline: 'none',
};

const LABEL_STYLE: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  color: 'var(--text-muted)',
  marginBottom: 6,
  letterSpacing: '0.05em',
  textTransform: 'uppercase' as const,
};

// ─── inline field row (reuses existing .modal-row / .modal-key / .modal-val) ─
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="modal-row">
      <span className="modal-key">{label}</span>
      <span className="modal-val">{children}</span>
    </div>
  );
}

// ─── Component ───────────────────────────────────────────────────────────────

export const Devices: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);

  // ── Simulation state ─────────────────────────────────────────────────────
  const [simDevice, setSimDevice] = useState<string>(mockDevices[0].device_id);
  const [simFlow, setSimFlow]     = useState<string>(mockPolicies[0].flow_id);
  const [simMessage, setSimMessage] = useState<string>('Temperature = 23.4 C');
  const [simMode, setSimMode]     = useState<SecurityMode>('CLASSICAL');
  const [simLoading, setSimLoading] = useState(false);
  const [simResult, setSimResult]  = useState<TransmissionResult | null>(null);
  const [simMocked, setSimMocked]  = useState(false);
  const [simError, setSimError]   = useState<string | null>(null);

  useEffect(() => {
    getDevices().then(({ data }) => setDevices(data));
  }, []);

  // When device changes, keep user selection clean without forced resets
  function handleDeviceChange(deviceId: string) {
    setSimDevice(deviceId);
    setSimResult(null);
    setSimError(null);
  }

  // Derive selected device object for live hints
  const selectedDevice = mockDevices.find((d) => d.device_id === simDevice);
  const selectedPolicy = mockPolicies.find((p) => p.flow_id === simFlow);

  async function runSimulation() {
    setSimLoading(true);
    setSimResult(null);
    setSimError(null);

    const { result, mocked, error } = await simulateTransmission(
      { device_id: simDevice, flow_id: simFlow, requested_mode: simMode },
      simMessage
    );

    setSimResult(result);
    setSimMocked(mocked);
    if (error && mocked) {
      setSimError(error);
    }
    setSimLoading(false);
  }

  // Floor compatibility helper (used in matrix)
  function canSatisfyFloor(device: Device, minimum_mode: SecurityMode): boolean {
    const minLevel = SECURITY_LEVEL[minimum_mode];
    return device.supported_modes.some((m) => SECURITY_LEVEL[m] >= minLevel);
  }

  const gw = simResult?.gateway;
  const cr = simResult?.crypto;

  // Decision colour for result border accent
  const decisionColor =
    gw?.decision === 'ALLOW'
      ? 'var(--green)'
      : gw?.decision === 'FLOOR_UNREACHABLE'
      ? 'var(--amber)'
      : 'var(--red)';

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Devices</h1>
        <p className="page-subtitle">
          Gateway-registered device capability registry and transmission simulator
        </p>
      </div>

      <div className="page-body">

        {/* ══════════════════════════════════════════════════════════════════
            DEVICE SIMULATION PANEL
        ══════════════════════════════════════════════════════════════════ */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Radio size={14} color="var(--accent-cyan)" />
              Device Transmission Simulator
            </span>
            {simMocked && simResult && (
              <span className="mock-badge">MOCK</span>
            )}
          </div>

          <div className="card-body">
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 18 }}>
              Simulate a device sending data through the gateway. Sensitivity is resolved from the
              trusted flow policy — not from the device. Device capability is checked separately.
            </p>

            {/* ── Selector grid ────────────────────────────────────────── */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))',
                gap: 14,
                marginBottom: 14,
              }}
            >
              {/* Device */}
              <div>
                <label htmlFor="sim-device" style={LABEL_STYLE}>Device</label>
                <select
                  id="sim-device"
                  value={simDevice}
                  onChange={(e) => handleDeviceChange(e.target.value)}
                  style={SELECT_STYLE}
                >
                  {mockDevices.map((d) => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.device_id}
                    </option>
                  ))}
                </select>
                {selectedDevice && (
                  <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {selectedDevice.supported_modes.map((m) => (
                      <ModeBadge key={m} mode={m} />
                    ))}
                  </div>
                )}
              </div>

              {/* Flow / Data Type */}
              <div>
                <label htmlFor="sim-flow" style={LABEL_STYLE}>Flow / Data Type</label>
                <select
                  id="sim-flow"
                  value={simFlow}
                  onChange={(e) => {
                    const newFlow = e.target.value;
                    setSimFlow(newFlow);
                    setSimResult(null);
                    setSimError(null);
                    if (simMessage === 'Temperature = 23.4 C' || simMessage === 'Hello, this is temperature data') {
                      if (newFlow === 'emergency_stop') setSimMessage('Emergency stop activated');
                    } else if (simMessage === 'Emergency stop activated') {
                      if (newFlow === 'temperature_01') setSimMessage('Temperature = 23.4 C');
                    }
                  }}
                  style={SELECT_STYLE}
                >
                  {mockPolicies.map((p) => (
                    <option key={p.flow_id} value={p.flow_id}>
                      {p.flow_id}
                    </option>
                  ))}
                </select>
                {selectedPolicy && (
                  <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                    <SensitivityBadge sensitivity={selectedPolicy.sensitivity} />
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>floor:</span>
                    <ModeBadge mode={selectedPolicy.minimum_mode} />
                  </div>
                )}
              </div>

              {/* Requested Security Mode */}
              <div>
                <label htmlFor="sim-mode" style={LABEL_STYLE}>Requested Mode</label>
                <select
                  id="sim-mode"
                  value={simMode}
                  onChange={(e) => { setSimMode(e.target.value as SecurityMode); setSimResult(null); setSimError(null); }}
                  style={SELECT_STYLE}
                >
                  {SECURITY_MODES.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* ── Message textarea ─────────────────────────────────────── */}
            <div style={{ marginBottom: 14 }}>
              <label htmlFor="sim-message" style={LABEL_STYLE}>Payload / Message</label>
              <textarea
                id="sim-message"
                value={simMessage}
                onChange={(e) => setSimMessage(e.target.value)}
                rows={2}
                placeholder="Enter the data payload this device will send…"
                style={{
                  width: '100%',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  color: 'var(--text-primary)',
                  fontSize: 13,
                  padding: '8px 10px',
                  fontFamily: 'inherit',
                  resize: 'vertical',
                  outline: 'none',
                }}
              />
            </div>

            {/* ── Run button ───────────────────────────────────────────── */}
            <button
              onClick={runSimulation}
              disabled={simLoading || !simMessage.trim()}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 18px',
                background: simLoading ? 'var(--border)' : 'var(--accent-cyan)',
                color: simLoading ? 'var(--text-muted)' : '#fff',
                border: 'none',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                cursor: simLoading || !simMessage.trim() ? 'not-allowed' : 'pointer',
                transition: 'opacity 0.15s',
                marginBottom: 18,
              }}
            >
              <Radio size={13} />
              {simLoading ? 'Transmitting…' : 'Send to Gateway'}
            </button>

            {/* ── Loading spinner ──────────────────────────────────────── */}
            {simLoading && (
              <div className="empty-state" style={{ padding: '16px 0' }}>
                <div
                  style={{
                    width: 20,
                    height: 20,
                    border: '2px solid var(--border)',
                    borderTop: '2px solid var(--accent-cyan)',
                    borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                    margin: '0 auto 10px',
                  }}
                />
                Sending to gateway…
              </div>
            )}

            {simError && (
              <div
                style={{
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  borderRadius: 6,
                  padding: '10px 14px',
                  marginBottom: 14,
                  fontSize: 12,
                  color: 'var(--red)',
                }}
              >
                {simError}
              </div>
            )}

            {/* ── Empty state ──────────────────────────────────────────── */}
            {!simResult && !simLoading && (
              <div className="empty-state" style={{ padding: '16px 0' }}>
                Select a device, flow, and message, then click Send to Gateway.
              </div>
            )}

            {/* ════════════════════════════════════════════════════════════
                RESULT PANEL
            ════════════════════════════════════════════════════════════ */}
            {simResult && gw && !simLoading && (
              <div
                style={{
                  borderTop: '2px solid ' + decisionColor,
                  paddingTop: 16,
                  marginTop: 4,
                }}
              >
                {/* Section label */}
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: '0.06em',
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    marginBottom: 14,
                  }}
                >
                  Gateway Result
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>

                  {/* ── Left column — input summary ── */}
                  <div>
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        letterSpacing: '0.07em',
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        marginBottom: 8,
                      }}
                    >
                      Transmission
                    </div>
                    <Row label="Device">{simDevice}</Row>
                    <Row label="Flow">{gw.flow_id}</Row>
                    <Row label="Message">
                      <span
                        style={{
                          fontSize: 11,
                          color: 'var(--text-secondary)',
                          fontStyle: 'italic',
                          maxWidth: 180,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          display: 'block',
                          textAlign: 'right',
                        }}
                        title={simResult.message}
                      >
                        "{simResult.message}"
                      </span>
                    </Row>
                    <Row label="Requested Mode">
                      <ModeBadge mode={gw.requested_mode} />
                    </Row>
                  </div>

                  {/* ── Right column — decision ── */}
                  <div>
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        letterSpacing: '0.07em',
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        marginBottom: 8,
                      }}
                    >
                      Policy Decision
                    </div>
                    <Row label="Decision">
                      <DecisionBadge decision={gw.decision} />
                    </Row>
                    <Row label="Sensitivity">
                      {gw.sensitivity
                        ? <SensitivityBadge sensitivity={gw.sensitivity} />
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                    </Row>
                    <Row label="Security Floor">
                      {gw.minimum_mode
                        ? <ModeBadge mode={gw.minimum_mode} />
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                    </Row>
                    <Row label="Reason">
                      <span
                        style={{
                          fontSize: 11,
                          color: 'var(--text-secondary)',
                          textAlign: 'right',
                          maxWidth: 200,
                          display: 'block',
                        }}
                      >
                        {gw.reason}
                      </span>
                    </Row>
                    <Row label="Policy Version">
                      {gw.policy_version != null ? `v${gw.policy_version}` : '—'}
                    </Row>
                    <Row label="Authority">{gw.authority_id ?? '—'}</Row>
                  </div>
                </div>

                {/* ── Crypto / Data-path stage ─────────────────────────── */}
                <div
                  style={{
                    marginTop: 20,
                    paddingTop: 16,
                    borderTop: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      letterSpacing: '0.07em',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                      marginBottom: 12,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    {gw.decision === 'ALLOW'
                      ? <Lock size={11} color="var(--green)" />
                      : <Unlock size={11} color="var(--text-muted)" />}
                    Crypto / Data Path
                    {cr && (
                      <span
                        style={{
                          marginLeft: 4,
                          fontSize: 10,
                          padding: '1px 6px',
                          borderRadius: 3,
                          background: cr.crypto_status === 'SECURE' ? 'rgba(5, 150, 105, 0.1)' : 'rgba(217, 119, 6, 0.1)',
                          color: cr.crypto_status === 'SECURE' ? 'var(--green)' : 'var(--amber)',
                          border: `1px solid ${cr.crypto_status === 'SECURE' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245,158,11,0.2)'}`,
                        }}
                      >
                        {cr.crypto_status === 'SECURE' ? 'LOCAL ROUND-TRIP' : cr.crypto_status ?? 'DEMO'}
                      </span>
                    )}
                  </div>

                  {gw.decision !== 'ALLOW' ? (
                    <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      Transmission was not allowed by the gateway — no crypto processing performed.
                    </p>
                  ) : cr ? (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>
                      <Row label="Algorithm">
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {cr.algorithm ?? '—'}
                        </span>
                      </Row>
                      <Row label="Crypto Status">
                        <span
                          style={{
                            fontSize: 11,
                            color: cr.crypto_status === 'SECURE' ? 'var(--green)' : 'var(--text-muted)',
                          }}
                        >
                          {cr.crypto_status === 'SECURE' ? 'Encryption & Decryption Successful' : cr.crypto_status ?? '—'}
                        </span>
                      </Row>
                      <Row label="Ciphertext">
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          {cr.ciphertext_hex
                            ? `${cr.ciphertext_hex.slice(0, 24)}… (${Math.round(cr.ciphertext_hex.length / 2)} bytes)`
                            : '—'}
                        </span>
                      </Row>
                      <Row label="KEM Key">
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          {cr.kem_encapsulated_key_hex
                            ? `${cr.kem_encapsulated_key_hex.slice(0, 24)}… (${Math.round(cr.kem_encapsulated_key_hex.length / 2)} bytes)`
                            : '—'}
                        </span>
                      </Row>
                      <Row label="Decrypted Message">
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                          {cr.decrypted_message
                            ? `"${cr.decrypted_message}"`
                            : '—'}
                        </span>
                      </Row>
                    </div>
                  ) : null}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            REGISTERED DEVICES TABLE  (unchanged)
        ══════════════════════════════════════════════════════════════════ */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <Cpu size={14} color="var(--accent-cyan)" />
              Registered Devices
            </span>
            <span className="mock-badge">DEMO DATA</span>
          </div>
          <DeviceTable devices={devices} />
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            FLOOR COMPATIBILITY MATRIX  (unchanged)
        ══════════════════════════════════════════════════════════════════ */}
        <div className="card section">
          <div className="card-header">
            <span className="card-title">
              <AlertTriangle size={14} color="var(--amber)" />
              Floor Compatibility Matrix
            </span>
          </div>
          <div className="card-body">
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Shows which devices can satisfy each flow's minimum security floor.
              A device that cannot meet the floor receives FLOOR_UNREACHABLE.
            </p>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    {mockPolicies.map((p) => (
                      <th key={p.flow_id}>
                        {p.flow_id}
                        <div style={{ display: 'flex', marginTop: 3 }}>
                          <ModeBadge mode={p.minimum_mode} />
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.device_id}>
                      <td className="mono">{device.device_id}</td>
                      {mockPolicies.map((policy) => {
                        const ok = canSatisfyFloor(device, policy.minimum_mode);
                        return (
                          <td key={policy.flow_id}>
                            {ok ? (
                              <span
                                className="badge"
                                style={{
                                  background: 'rgba(16, 185, 129, 0.1)',
                                  color: 'var(--green)',
                                  borderColor: 'rgba(16, 185, 129, 0.2)',
                                }}
                              >
                                ✓ REACHABLE
                              </span>
                            ) : (
                              <span
                                className="badge"
                                style={{
                                  background: 'rgba(245, 158, 11, 0.1)',
                                  color: 'var(--amber)',
                                  borderColor: 'rgba(245, 158, 11, 0.2)',
                                }}
                              >
                                ✗ UNREACHABLE
                              </span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 12 }}>
              ⓘ Capabilities are gateway-registered, not hardware-attested.
            </p>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
};
