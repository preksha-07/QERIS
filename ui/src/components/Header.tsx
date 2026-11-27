import React from 'react';
import { RefreshCw, Cloud, Lock } from 'lucide-react';
import type { GatewayStatus } from '../types/qeris';

interface HeaderProps {
  status: GatewayStatus | null;
  onRefresh?: () => void;
  title: string;
  description: string;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  onRefresh,
  title,
  description,
}) => {
  const isOnline = status?.online ?? false;

  return (
    <header className="header-bar">
      <div className="header-left">
        <div className="header-title-wrap">
          <h1 className="header-page-title">{title}</h1>
          <p className="header-page-desc">{description}</p>
        </div>
      </div>

      <div className="header-right">
        {/* Security Invariant Indicator */}
        <div className="qeris-badge badge-neutral" style={{ display: 'flex', gap: 6, padding: '5px 12px' }}>
          <Lock size={13} color="var(--accent-cyan)" />
          <span style={{ fontSize: 11, fontWeight: 600 }}>Security Invariant I1-I8:</span>
          <span style={{ color: 'var(--status-allow)', fontWeight: 700 }}>ACTIVE</span>
        </div>

        {/* Gateway Connection Pill */}
        <div className={`qeris-badge ${isOnline ? 'badge-allow' : 'badge-reject'}`} style={{ padding: '5px 12px' }}>
          <span className={`pulse-dot ${isOnline ? 'online' : 'offline'}`} />
          <span>Gateway: {isOnline ? '127.0.0.1:8000' : 'OFFLINE'}</span>
        </div>

        {/* Cloud TLS status */}
        <div className="qeris-badge badge-info" style={{ padding: '5px 12px' }}>
          <Cloud size={13} />
          <span>Cloud Forwarder: Mutual TLS</span>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            className="btn btn-secondary"
            style={{ padding: '6px 12px', height: 32 }}
            title="Refresh Live Data"
          >
            <RefreshCw size={13} />
            <span>Sync</span>
          </button>
        )}
      </div>
    </header>
  );
};
