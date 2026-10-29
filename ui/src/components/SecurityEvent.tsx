import React from 'react';
import type { SecurityEvent } from '../types/qeris';
import { ShieldX, AlertTriangle } from 'lucide-react';
import { DecisionBadge, ModeBadge, SensitivityBadge } from './SecurityBadge';

interface SecurityEventCardProps {
  event: SecurityEvent;
}

export const SecurityEventCard: React.FC<SecurityEventCardProps> = ({
  event,
}) => {
  const isDowngrade = event.type === 'DOWNGRADE_BLOCKED';
  const isFloorUnreachable = event.type === 'FLOOR_UNREACHABLE';

  const title = isDowngrade
    ? 'Downgrade Attempt Blocked'
    : isFloorUnreachable
    ? 'Security Floor Unreachable'
    : 'Security Event';

  const time = new Date(event.timestamp).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div
      className={`security-event-card ${isFloorUnreachable ? 'floor-unreachable' : ''}`}
      style={
        isFloorUnreachable
          ? {
              borderColor: 'rgba(245, 158, 11, 0.3)',
              background: 'rgba(245, 158, 11, 0.04)',
            }
          : {}
      }
    >
      <div
        className="security-event-header"
        style={
          isFloorUnreachable ? { borderColor: 'rgba(245, 158, 11, 0.2)', background: 'rgba(245, 158, 11, 0.08)', color: 'var(--amber)' } : {}
        }
      >
        {isDowngrade ? <ShieldX size={13} /> : <AlertTriangle size={13} />}
        <span>SECURITY EVENT</span>
        <span style={{ marginLeft: 'auto', fontWeight: 400, textTransform: 'none', letterSpacing: 0, color: 'var(--text-muted)', fontSize: 11 }}>
          {time}
        </span>
      </div>
      <div className="security-event-body">
        <div style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
            {title}
          </span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Flow</span>
          <span className="security-event-val">{event.flow_id}</span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Device</span>
          <span className="security-event-val">{event.device_id}</span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Sensitivity</span>
          <span className="security-event-val">
            <SensitivityBadge sensitivity={event.sensitivity} />
          </span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Required Security Floor</span>
          <span className="security-event-val">
            <ModeBadge mode={event.required_mode} />
          </span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Requested Mode</span>
          <span className="security-event-val">
            <ModeBadge mode={event.requested_mode} />
          </span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Decision</span>
          <span className="security-event-val">
            <DecisionBadge decision={event.decision} />
          </span>
        </div>
        <div className="security-event-row">
          <span className="security-event-key">Reason</span>
          <span className="security-event-val" style={{ maxWidth: 240, textAlign: 'right', fontFamily: 'inherit', fontSize: 11, color: 'var(--text-secondary)' }}>
            {event.reason}
          </span>
        </div>
      </div>
    </div>
  );
};
