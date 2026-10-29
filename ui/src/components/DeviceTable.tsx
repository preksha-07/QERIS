import React from 'react';
import type { Device } from '../types/qeris';
import { SECURITY_LEVEL } from '../types/qeris';
import type { SecurityMode } from '../types/qeris';
import { ModeBadge } from './SecurityBadge';
import { Cpu } from 'lucide-react';

interface DeviceTableProps {
  devices: Device[];
}

function getHighestMode(modes: SecurityMode[]): SecurityMode {
  return modes.reduce((best, m) =>
    SECURITY_LEVEL[m] > SECURITY_LEVEL[best] ? m : best
  );
}

export const DeviceTable: React.FC<DeviceTableProps> = ({ devices }) => {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Device</th>
            <th>Supported Modes</th>
            <th>Highest Supported</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => {
            const highest = getHighestMode(device.supported_modes);
            const isLimited = device.status === 'LIMITED';
            return (
              <tr key={device.device_id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Cpu size={14} color="var(--text-muted)" />
                    <span className="mono">{device.device_id}</span>
                  </div>
                </td>
                <td>
                  <div className="mode-tags">
                    {device.supported_modes.map((m) => (
                      <ModeBadge key={m} mode={m} />
                    ))}
                  </div>
                </td>
                <td>
                  <ModeBadge mode={highest} />
                </td>
                <td>
                  {isLimited ? (
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(245, 158, 11, 0.1)',
                        color: 'var(--amber)',
                        borderColor: 'rgba(245, 158, 11, 0.2)',
                      }}
                    >
                      LIMITED
                    </span>
                  ) : device.status === 'OFFLINE' ? (
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: 'var(--red)',
                        borderColor: 'rgba(239, 68, 68, 0.2)',
                      }}
                    >
                      OFFLINE
                    </span>
                  ) : (
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(16, 185, 129, 0.1)',
                        color: 'var(--green)',
                        borderColor: 'rgba(16, 185, 129, 0.2)',
                      }}
                    >
                      READY
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
