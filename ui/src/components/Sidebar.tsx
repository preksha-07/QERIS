import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  Cpu,
  Terminal,
  ShieldCheck,
  RefreshCw,
  Cloud,
  FileSpreadsheet,
  Radio,
} from 'lucide-react';

interface SidebarProps {
  gatewayOnline: boolean;
  baselineMode?: string;
  policyVersion?: number;
}

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Overview' },
  { to: '/flows', icon: Activity, label: 'Live Flow Monitor' },
  { to: '/devices', icon: Cpu, label: 'Network & Devices' },
  { to: '/playground', icon: Terminal, label: 'Playground' },
  { to: '/policies', icon: ShieldCheck, label: 'Policies' },
  { to: '/security', icon: RefreshCw, label: 'Security & Recovery' },
  { to: '/cloud', icon: Cloud, label: 'Cloud & Telemetry' },
  { to: '/reports', icon: FileSpreadsheet, label: 'Reports & Research' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  gatewayOnline,
  baselineMode = 'B0_PROPOSED',
  policyVersion = 1,
}) => {
  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">
          <div style={{
            width: 28,
            height: 28,
            borderRadius: 7,
            background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            boxShadow: '0 2px 8px rgba(2, 132, 199, 0.3)'
          }}>
            <Radio size={16} />
          </div>
          <span>QERIS</span>
        </div>
        <div className="sidebar-brand-sub">
          <span className="pulse-dot online" style={{ width: 6, height: 6 }} />
          Post-Quantum Security Gateway
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Command Center</div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Sidebar System Telemetry Footer */}
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>Gateway State</span>
          <span className={`qeris-badge ${gatewayOnline ? 'badge-allow' : 'badge-reject'}`}>
            <span className={`pulse-dot ${gatewayOnline ? 'online' : 'offline'}`} />
            {gatewayOnline ? 'CONNECTED' : 'DISCONNECTED'}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11 }}>
          <span style={{ color: 'var(--text-muted)' }}>Active Baseline</span>
          <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
            {baselineMode}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11 }}>
          <span style={{ color: 'var(--text-muted)' }}>Policy Epoch</span>
          <span className="mono" style={{ color: 'var(--text-secondary)' }}>
            v{policyVersion} (Root Verified)
          </span>
        </div>
      </div>
    </aside>
  );
};
