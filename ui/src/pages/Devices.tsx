import React, { useEffect, useState } from 'react';
import { Cpu, AlertTriangle } from 'lucide-react';
import { DeviceTable } from '../components/DeviceTable';
import { getDevices } from '../services/api';
import { mockPolicies } from '../data/mockData';
import type { Device } from '../types/qeris';
import { SECURITY_LEVEL } from '../types/qeris';
import type { SecurityMode } from '../types/qeris';
import { ModeBadge } from '../components/SecurityBadge';

export const Devices: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);

  useEffect(() => {
    getDevices().then(({ data }) => setDevices(data));
  }, []);

  // Compute floor compatibility matrix
  function canSatisfyFloor(device: Device, minimum_mode: SecurityMode): boolean {
    const minLevel = SECURITY_LEVEL[minimum_mode];
    return device.supported_modes.some(
      (m) => SECURITY_LEVEL[m] >= minLevel
    );
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Devices</h1>
        <p className="page-subtitle">
          Gateway-registered device capability registry
        </p>
      </div>

      <div className="page-body">
        {/* Device Table */}
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

        {/* Floor Compatibility Matrix */}
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
    </div>
  );
};
