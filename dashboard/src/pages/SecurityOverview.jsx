import React, { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import { Badge } from '../components/Badge.jsx';

export function SecurityOverview({ onNavigate }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function fetchOverview() {
    try {
      setLoading(true);
      const res = await api.getOverview();
      if (res.success && res.data) {
        setData(res.data);
        setError(null);
      }
    } catch (err) {
      setError(err.message || 'Failed to load security overview');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchOverview();
  }, []);

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Security Overview</h1>
            <p className="page-desc">Loading live security posture from VaultBase engine...</p>
          </div>
        </div>
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          Loading real-time security data...
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Security Overview</h1>
            <p className="page-desc">VaultBase security posture summary</p>
          </div>
        </div>
        <div className="card" style={{ textAlign: 'center', padding: 40, borderColor: 'var(--status-critical-border)' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
          <div style={{ fontWeight: 600, color: 'var(--status-critical)', marginBottom: 8 }}>{error}</div>
          <button type="button" className="btn btn-secondary" onClick={fetchOverview}>
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const { user, sessions, devices, biometrics, risk, recentEvents, alerts } = data;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-desc">Real-time status of your authenticated sessions, devices, and risk posture</p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={fetchOverview}>
          🔄 Refresh
        </button>
      </div>

      {/* Posture Banner */}
      <div className={`posture-banner ${risk.level}`}>
        <div className="posture-info">
          <div className="posture-icon">
            {risk.level === 'LOW' && '🛡️'}
            {risk.level === 'MEDIUM' && '⚠️'}
            {risk.level === 'HIGH' && '🚨'}
            {risk.level === 'CRITICAL' && '🛑'}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 18, fontWeight: 700 }}>Security Posture: {risk.level} Risk</span>
              <Badge variant={risk.level}>{risk.score}/100 Score</Badge>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
              {risk.level === 'LOW' && 'Your account context is normal. No suspicious anomalies detected.'}
              {risk.level === 'MEDIUM' && 'Slight context deviation detected. Additional factor authentication recommended.'}
              {risk.level === 'HIGH' && 'Elevated risk detected. Biometric step-up authentication is active.'}
              {risk.level === 'CRITICAL' && 'Severe risk anomalies detected! Cryptographic WebAuthn authentication required.'}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Evaluated At</div>
          <div style={{ fontSize: 12, fontWeight: 500 }}>
            {new Date(risk.lastEvaluatedAt).toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid-4">
        <div className="card stat-card">
          <div className="stat-label">
            <span>Active Sessions</span>
            <span style={{ cursor: 'pointer' }} onClick={() => onNavigate('sessions')}>🔗</span>
          </div>
          <div className="stat-value" style={{ color: sessions.activeCount > 0 ? '#818cf8' : 'var(--text-muted)' }}>
            {sessions.activeCount}
          </div>
          <div className="stat-subtext">{sessions.totalCount} total session records</div>
        </div>

        <div className="card stat-card">
          <div className="stat-label">
            <span>Trusted Devices</span>
            <span style={{ cursor: 'pointer' }} onClick={() => onNavigate('devices')}>🔗</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--status-low)' }}>
            {devices.trustedCount}
          </div>
          <div className="stat-subtext">{devices.revokedCount} revoked device{devices.revokedCount !== 1 ? 's' : ''}</div>
        </div>

        <div className="card stat-card">
          <div className="stat-label">
            <span>Biometric Profile</span>
            <span>🧬</span>
          </div>
          <div className="stat-value" style={{ fontSize: 24, margin: '12px 0 8px' }}>
            {biometrics.faceEnrolled ? 'Enrolled' : 'Not Set'}
          </div>
          <div className="stat-subtext">
            {biometrics.webauthnCredentialsCount} WebAuthn FIDO2 key{biometrics.webauthnCredentialsCount !== 1 ? 's' : ''}
          </div>
        </div>

        <div className="card stat-card">
          <div className="stat-label">
            <span>Security Alerts</span>
            <span style={{ cursor: 'pointer' }} onClick={() => onNavigate('alerts')}>🔗</span>
          </div>
          <div className="stat-value" style={{ color: alerts.length > 0 ? 'var(--status-critical)' : 'var(--status-low)' }}>
            {alerts.length}
          </div>
          <div className="stat-subtext">
            {alerts.length === 0 ? 'No active critical alerts' : 'Requires your attention'}
          </div>
        </div>
      </div>

      {/* Recent Security Activity Table */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700 }}>Recent Security & Authentication Events</h2>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => onNavigate('audit-logs')}>
            View All History →
          </button>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents && recentEvents.length > 0 ? (
                recentEvents.map((evt, idx) => (
                  <tr key={evt.id || idx}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {new Date(evt.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{evt.type}</span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{evt.category}</span>
                    </td>
                    <td>
                      <Badge variant={evt.severity}>{evt.severity}</Badge>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                      {evt.details ? (
                        typeof evt.details === 'string' ? evt.details : (
                          evt.details.reason ||
                          (evt.details.signals ? `Signals: ${evt.details.signals.map(s => s.name).join(', ') || 'None'}` : '') ||
                          JSON.stringify(evt.details)
                        )
                      ) : '—'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                    No recent security events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
