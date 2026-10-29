import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  Cpu,
  ShieldCheck,
  FileText,
  ScrollText,
  Radio,
} from 'lucide-react';

interface SidebarProps {
  gatewayOnline: boolean;
}

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/flows', icon: Activity, label: 'Flow Monitor' },
  { to: '/devices', icon: Cpu, label: 'Devices' },
  { to: '/policies', icon: FileText, label: 'Policies' },
  { to: '/security', icon: ShieldCheck, label: 'Security & Recovery' },
  { to: '/audit', icon: ScrollText, label: 'Audit Logs' },
];

export const Sidebar: React.FC<SidebarProps> = ({ gatewayOnline }) => {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <Radio size={18} color="var(--accent-cyan)" />
          <span className="sidebar-brand-name">QERIS</span>
        </div>
        <div className="sidebar-brand-sub">Post-Quantum Security Gateway</div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `nav-item${isActive ? ' active' : ''}`
            }
          >
            <Icon className="nav-icon" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="gateway-status-label">Gateway</div>
        <div className="gateway-status-value" style={{ marginTop: 4 }}>
          <span className={`status-dot ${gatewayOnline ? 'online' : 'offline'}`} />
          <span style={{ color: gatewayOnline ? 'var(--green)' : 'var(--red)' }}>
            {gatewayOnline ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>
        <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-muted)' }}>
          QERIS-GATEWAY · v1.0.0
        </div>
      </div>
    </aside>
  );
};
