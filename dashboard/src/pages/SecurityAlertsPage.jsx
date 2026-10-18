import React from 'react';
import { useSocket } from '../context/SocketContext.jsx';
import { Badge } from '../components/Badge.jsx';

export function SecurityAlertsPage() {
  const { alerts, connected, dismissAlert, clearAllAlerts } = useSocket();

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Real-Time Security Alerts</h1>
          <p className="page-desc">Live streaming notifications for suspicious logins, session hijack events, and device revocations</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="socket-status">
            <span className={`socket-dot ${connected ? 'connected' : ''}`}></span>
            <span>{connected ? 'Event Bus Connected' : 'Event Bus Disconnected'}</span>
          </div>
          {alerts.length > 0 && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={clearAllAlerts}>
              Clear All Alerts
            </button>
          )}
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>🛡️</div>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>No Active Security Alerts</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 400, margin: '0 auto' }}>
            VaultBase is actively monitoring your authenticated sessions and hardware devices in real time. Any high-confidence threats will appear here immediately.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className="card"
              style={{
                borderColor: 'var(--status-critical-border)',
                background: 'linear-gradient(90deg, rgba(239, 68, 68, 0.08) 0%, var(--bg-surface) 100%)',
                padding: '16px 20px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                  <div style={{ fontSize: 24 }}>🚨</div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontWeight: 700, fontSize: 14 }}>{alert.event}</span>
                      <Badge variant="CRITICAL">ALERT</Badge>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div style={{ fontSize: 13, color: 'var(--text-primary)', marginTop: 4 }}>
                      {alert.message}
                    </div>
                    {alert.details && (
                      <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-secondary)', marginTop: 6, background: 'var(--bg-card)', padding: '6px 10px', borderRadius: 6 }}>
                        {JSON.stringify(alert.details)}
                      </div>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => dismissAlert(alert.id)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
