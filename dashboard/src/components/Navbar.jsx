import React from 'react';
import { useAuth } from '../context/AuthContext.jsx';
import { useSocket } from '../context/SocketContext.jsx';

export function Navbar() {
  const { user, logout } = useAuth();
  const { connected, alerts } = useSocket();

  return (
    <header className="top-header">
      <div className="header-brand">
        <div className="brand-icon">🛡️</div>
        <div>
          <div className="brand-title">VaultBase</div>
          <div className="brand-subtitle">Security Control Center</div>
        </div>
      </div>

      <div className="header-right">
        <div className="socket-status" title={connected ? 'Live event stream active' : 'Disconnected from event stream'}>
          <span className={`socket-dot ${connected ? 'connected' : ''}`}></span>
          <span>{connected ? 'Live Monitoring' : 'Offline'}</span>
        </div>

        {alerts.length > 0 && (
          <div
            style={{
              background: 'rgba(239,68,68,0.2)',
              color: '#ef4444',
              padding: '4px 8px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <span>⚠️</span> {alerts.length} Alert{alerts.length > 1 ? 's' : ''}
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>{user?.email}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Status: Active</div>
          </div>
          <button type="button" className="btn btn-sm btn-secondary" onClick={logout}>
            Sign Out
          </button>
        </div>
      </div>
    </header>
  );
}
