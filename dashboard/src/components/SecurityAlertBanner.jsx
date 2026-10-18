import React from 'react';
import { useSocket } from '../context/SocketContext.jsx';

export function SecurityAlertBanner() {
  const { alerts, dismissAlert } = useSocket();

  if (!alerts || alerts.length === 0) return null;

  return (
    <div style={{ marginBottom: 20 }}>
      {alerts.slice(0, 3).map((alert) => (
        <div key={alert.id} className="alert-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 20 }}>🚨</span>
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{alert.event}</div>
              <div style={{ fontSize: 12, opacity: 0.9 }}>{alert.message}</div>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => dismissAlert(alert.id)}
            style={{ borderColor: 'rgba(239,68,68,0.4)', background: 'transparent' }}
          >
            Dismiss
          </button>
        </div>
      ))}
    </div>
  );
}
