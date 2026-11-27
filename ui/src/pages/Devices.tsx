import React, { useEffect, useState } from 'react';
import { Cpu, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { Header } from '../components/Header';
import { getGatewayStatus, getDevices } from '../services/api';
import type { GatewayStatus, Device } from '../types/qeris';

export const Devices: React.FC = () => {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);

  const fetchData = async () => {
    const [gwStatus, devList] = await Promise.all([
      getGatewayStatus(),
      getDevices(),
    ]);
    setStatus(gwStatus);
    setDevices(devList);
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Header
        status={status}
        onRefresh={fetchData}
        title="Network & Devices"
        description="Registered edge node capability profiles, cryptographic capabilities, and security-floor feasibility"
      />

      <div className="main-content">
        {/* Device Profiles Table */}
        <div className="qeris-card" style={{ marginBottom: 24, padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 className="qeris-card-title">
                <Cpu size={16} color="var(--accent-cyan)" />
                Registered Device Capability Profiles
              </h2>
              <p className="qeris-card-subtitle">
                Device profiles evaluated against minimum required security floors
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">4 HETEROGENEOUS NODES</span>
          </div>

          <div className="qeris-table-container" style={{ border: 'none' }}>
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Device Identifier</th>
                  <th>Hardware Class</th>
                  <th>Supported Security Modes</th>
                  <th>MTU (Bytes)</th>
                  <th>RAM Available</th>
                  <th>Quarantine State</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => {
                  const isEsp32 = device.device_id.includes('esp32');
                  const isNordic = device.device_id.includes('nordic');
                  const isLinux = device.device_id.includes('linux');

                  return (
                    <tr key={device.device_id}>
                      <td className="mono" style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                        {device.device_id}
                      </td>
                      <td>
                        <span className="qeris-badge badge-neutral" style={{ fontSize: 10.5 }}>
                          {isEsp32 ? 'ESP32 (Constrained IoT)' : isNordic ? 'Nordic nRF (Sensor)' : isLinux ? 'Linux Edge (Gateway Node)' : 'Standard Node'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {device.supported_modes.map((mode) => (
                            <span key={mode} className={`qeris-badge ${
                              mode === 'PQC' ? 'badge-allow' : mode === 'HYBRID' ? 'badge-info' : 'badge-neutral'
                            }`} style={{ fontSize: 10 }}>
                              {mode}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="mono">{device.mtu ?? 1500} B</td>
                      <td className="mono">{device.ram_bytes ? `${Math.round(device.ram_bytes / 1024)} KB` : '64 KB'}</td>
                      <td>
                        {device.quarantined ? (
                          <span className="qeris-badge badge-reject">QUARANTINED</span>
                        ) : (
                          <span className="qeris-badge badge-allow">ACTIVE</span>
                        )}
                      </td>
                      <td>
                        <span className="qeris-badge badge-allow">
                          <CheckCircle2 size={12} /> {device.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Profile Compatibility Matrix */}
        <div className="qeris-card">
          <div className="qeris-card-header">
            <div>
              <h2 className="qeris-card-title">
                <ShieldCheck size={16} color="var(--status-allow)" />
                Security Profile Compatibility & Floor Feasibility Matrix
              </h2>
              <p className="qeris-card-subtitle">
                Cross-product of Device Hardware Constraints vs Required Policy Floors
              </p>
            </div>
            <span className="qeris-badge badge-neutral mono">INVARIANT I2 VERIFICATION</span>
          </div>

          <div className="qeris-table-container">
            <table className="qeris-table">
              <thead>
                <tr>
                  <th>Device ID</th>
                  <th>CLASSICAL (ECDH)</th>
                  <th>HYBRID (X25519 + ML-KEM)</th>
                  <th>PQC (Pure ML-KEM-512)</th>
                  <th>Feasible Floor Limit</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => {
                  const hasPqc = device.supported_modes.includes('PQC');
                  const hasHybrid = device.supported_modes.includes('HYBRID');
                  const hasClassical = device.supported_modes.includes('CLASSICAL');

                  return (
                    <tr key={`matrix-${device.device_id}`}>
                      <td className="mono" style={{ fontWeight: 600 }}>{device.device_id}</td>
                      <td>
                        {hasClassical ? (
                          <span className="qeris-badge badge-allow">COMPLIANT</span>
                        ) : (
                          <span className="qeris-badge badge-reject">UNSUPPORTED</span>
                        )}
                      </td>
                      <td>
                        {hasHybrid ? (
                          <span className="qeris-badge badge-allow">COMPLIANT</span>
                        ) : (
                          <span className="qeris-badge badge-reject">DEFICIENT</span>
                        )}
                      </td>
                      <td>
                        {hasPqc ? (
                          <span className="qeris-badge badge-allow">COMPLIANT</span>
                        ) : (
                          <span className="qeris-badge badge-unreachable">FLOOR UNREACHABLE</span>
                        )}
                      </td>
                      <td>
                        <span className="qeris-badge badge-neutral mono">
                          {hasPqc ? 'MAX: PQC' : hasHybrid ? 'MAX: HYBRID' : 'MAX: CLASSICAL'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
