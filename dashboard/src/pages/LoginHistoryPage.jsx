import React, { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import { Badge } from '../components/Badge.jsx';

export function LoginHistoryPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterLevel, setFilterLevel] = useState('ALL');

  async function fetchLogs() {
    try {
      setLoading(true);
      const res = await api.getAuditLogs();
      if (res.success && res.data) {
        setLogs(res.data.logs || []);
        setError(null);
      }
    } catch (err) {
      setError(err.message || 'Failed to load authentication audit logs');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
    if (filterLevel === 'ALL') return true;
    return log.riskLevel === filterLevel;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Login History & Audit Logs</h1>
          <p className="page-desc">Chronological record of authentication attempts, evaluated risk tiers, and required authentication factors</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select
            className="form-input"
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
            style={{ width: 'auto', padding: '6px 12px' }}
          >
            <option value="ALL">All Risk Levels</option>
            <option value="LOW">LOW Risk Only</option>
            <option value="MEDIUM">MEDIUM Risk Only</option>
            <option value="HIGH">HIGH Risk Only</option>
            <option value="CRITICAL">CRITICAL Risk Only</option>
          </select>
          <button type="button" className="btn btn-secondary btn-sm" onClick={fetchLogs} disabled={loading}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          Loading authentication audit logs...
        </div>
      ) : error ? (
        <div className="card" style={{ textAlign: 'center', padding: 40, borderColor: 'var(--status-critical-border)' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
          <div style={{ fontWeight: 600, color: 'var(--status-critical)', marginBottom: 8 }}>{error}</div>
          <button type="button" className="btn btn-secondary" onClick={fetchLogs}>
            Retry
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>IP Address</th>
                <th>Device Fingerprint</th>
                <th>Risk Score & Tier</th>
                <th>Required Factors</th>
                <th>Decision</th>
                <th>Signals Detected</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log, idx) => (
                  <tr key={log.timestamp + idx}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {log.ip || '127.0.0.1'}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)' }}>
                      {log.deviceFingerprint || '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Badge variant={log.riskLevel}>{log.riskLevel}</Badge>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
                          ({log.riskScore}/100)
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {log.requiredFactors && log.requiredFactors.length > 0 ? (
                          log.requiredFactors.map((factor) => (
                            <span
                              key={factor}
                              style={{
                                background: 'var(--bg-card)',
                                border: '1px solid var(--border-color)',
                                padding: '2px 6px',
                                borderRadius: 4,
                                fontSize: 11,
                                textTransform: 'uppercase',
                                fontWeight: 600,
                              }}
                            >
                              {factor}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>None</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, fontSize: 12, color: 'var(--status-low)' }}>
                        {log.decision || 'CHALLENGE'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 12, maxWidth: 220 }}>
                      {log.signals && log.signals.length > 0 ? (
                        log.signals.map((s) => s.name).join(', ')
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>None</span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No audit records matching criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
