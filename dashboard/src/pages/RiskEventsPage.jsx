import React, { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import { Badge } from '../components/Badge.jsx';

export function RiskEventsPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function fetchEvents() {
    try {
      setLoading(true);
      const res = await api.getRiskEvents();
      if (res.success && res.data) {
        setEvents(res.data.events || []);
        setError(null);
      }
    } catch (err) {
      setError(err.message || 'Failed to load risk events');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchEvents();
  }, []);

  const signalDefinitions = [
    { name: 'REVOKED_DEVICE', weight: '+40', tier: 'HIGH/CRITICAL', desc: 'Authentication attempt originating from a previously revoked device' },
    { name: 'SESSION_HIJACK_HISTORY', weight: '+35', tier: 'CRITICAL', desc: 'Recent session hijack detected for this account within the last hour' },
    { name: 'NEW_DEVICE', weight: '+30', tier: 'MEDIUM', desc: 'First-time authentication from an unrecognized device hardware fingerprint' },
    { name: 'FAILED_ATTEMPTS', weight: '+25', tier: 'MEDIUM/HIGH', desc: 'Recent multiple failed password or OTP verification attempts' },
    { name: 'IP_CHANGE', weight: '+20', tier: 'LOW/MEDIUM', desc: 'Network address differs from previous successful login context' },
    { name: 'UNUSUAL_HOUR', weight: '+15', tier: 'LOW', desc: 'Authentication attempt during off-peak hours (before 6am or after 10pm)' },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Risk Engine & Security Signals</h1>
          <p className="page-desc">Authoritative multi-signal risk evaluation model and security anomaly stream</p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={fetchEvents} disabled={loading}>
          🔄 Refresh
        </button>
      </div>

      {/* Model Weights Reference Cards */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 15, fontWeight: 700, marginBottom: 12 }}>Authoritative Risk Signals & Weight Model (0–100 Scale)</h2>
        <div className="grid-2">
          {signalDefinitions.map((sig) => (
            <div
              key={sig.name}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-color)',
                borderRadius: 8,
                padding: 12,
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: '#818cf8' }}>
                    {sig.name}
                  </span>
                  <Badge variant={sig.tier}>{sig.weight}</Badge>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                  {sig.desc}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Real Anomaly & Risk Events Stream */}
      <div className="card">
        <h2 style={{ fontSize: 15, fontWeight: 700, marginBottom: 14 }}>Recorded Security Anomalies & Context Changes</h2>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
            Loading risk events stream...
          </div>
        ) : error ? (
          <div style={{ textAlign: 'center', padding: 20, color: 'var(--status-critical)' }}>
            {error}
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event / Anomaly Type</th>
                  <th>Category</th>
                  <th>Context & Details</th>
                </tr>
              </thead>
              <tbody>
                {events.length > 0 ? (
                  events.map((evt, idx) => (
                    <tr key={evt.timestamp + idx}>
                      <td style={{ whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <span style={{ fontWeight: 600, color: evt.type.includes('HIJACK') || evt.type.includes('REVOKED') ? 'var(--status-critical)' : 'var(--text-primary)' }}>
                          {evt.type}
                        </span>
                      </td>
                      <td>
                        <Badge variant={evt.category === 'ANOMALY' ? 'HIGH' : 'LOW'}>
                          {evt.category}
                        </Badge>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {evt.details ? (
                          typeof evt.details === 'string' ? evt.details : (
                            evt.details.reason ||
                            (evt.details.error ? `Error: ${evt.details.error}` : '') ||
                            (evt.details.oldIP ? `IP: ${evt.details.oldIP} → ${evt.details.newIP}` : '') ||
                            JSON.stringify(evt.details)
                          )
                        ) : '—'}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                      No anomaly or risk events recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
