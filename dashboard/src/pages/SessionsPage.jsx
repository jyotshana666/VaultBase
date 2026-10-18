import React, { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Badge } from '../components/Badge.jsx';
import { Modal } from '../components/Modal.jsx';

export function SessionsPage() {
  const { sessionRecord, user } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState(null); // specific session jti or 'ALL'
  const [feedback, setFeedback] = useState(null);

  async function fetchSessions() {
    try {
      setLoading(true);
      const res = await api.getSessions();
      if (res.success && res.data) {
        setSessions(res.data.sessions || []);
        setError(null);
      }
    } catch (err) {
      setError(err.message || 'Failed to load active sessions');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchSessions();
  }, []);

  async function handleConfirmRevoke() {
    if (!revokeTarget) return;

    try {
      setActionLoading(true);
      if (revokeTarget === 'ALL') {
        const res = await api.revokeAllSessions();
        if (res.success) {
          setFeedback({ type: 'success', message: `All active sessions (${res.data.revokedCount}) have been revoked.` });
          await fetchSessions();
        }
      } else {
        const res = await api.revokeSession(revokeTarget.jti);
        if (res.success) {
          setFeedback({ type: 'success', message: `Session ${revokeTarget.jti.slice(0, 8)}… was successfully revoked.` });
          await fetchSessions();
        }
      }
    } catch (err) {
      setFeedback({ type: 'error', message: `Revocation failed: ${err.message}` });
    } finally {
      setActionLoading(false);
      setRevokeTarget(null);
    }
  }

  const activeCount = sessions.filter((s) => s.status === 'active').length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Active Sessions</h1>
          <p className="page-desc">Inspect all authenticated browser and extension sessions; revoke suspicious or unused tokens immediately</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button type="button" className="btn btn-secondary btn-sm" onClick={fetchSessions} disabled={loading}>
            🔄 Refresh
          </button>
          {activeCount > 1 && (
            <button
              type="button"
              className="btn btn-danger btn-sm"
              onClick={() => setRevokeTarget('ALL')}
            >
              Sign Out Everywhere
            </button>
          )}
        </div>
      </div>

      {feedback && (
        <div
          className="card"
          style={{
            marginBottom: 20,
            padding: 12,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderColor: feedback.type === 'error' ? 'var(--status-critical-border)' : 'var(--status-low-border)',
            background: feedback.type === 'error' ? 'var(--status-critical-bg)' : 'var(--status-low-bg)',
            color: feedback.type === 'error' ? 'var(--status-critical)' : 'var(--status-low)',
          }}
        >
          <span>{feedback.message}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setFeedback(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          Loading active session records...
        </div>
      ) : error ? (
        <div className="card" style={{ textAlign: 'center', padding: 40, borderColor: 'var(--status-critical-border)' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
          <div style={{ fontWeight: 600, color: 'var(--status-critical)', marginBottom: 8 }}>{error}</div>
          <button type="button" className="btn btn-secondary" onClick={fetchSessions}>
            Retry
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Client / User-Agent</th>
                <th>IP Address</th>
                <th>Context Shifts</th>
                <th>Status</th>
                <th>Issued At</th>
                <th>Last Active</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.length > 0 ? (
                sessions.map((s) => {
                  const isCurrent = sessionRecord && sessionRecord.jti === s.jti;
                  return (
                    <tr key={s.jti}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: 13 }}>
                            {s.jti ? `${s.jti.slice(0, 8)}…` : '—'}
                          </span>
                          {isCurrent && <Badge variant="CURRENT">Current</Badge>}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontSize: 12, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.userAgent}>
                          {s.userAgent || 'Chrome Browser'}
                        </div>
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)' }}>
                        {s.ip || '127.0.0.1'}
                      </td>
                      <td>
                        {s.contextChanges > 0 ? (
                          <span style={{ color: 'var(--status-medium)', fontWeight: 600 }}>
                            {s.contextChanges} change{s.contextChanges > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>0</span>
                        )}
                      </td>
                      <td>
                        <Badge variant={s.status}>{s.status}</Badge>
                      </td>
                      <td style={{ color: 'var(--text-secondary)' }}>
                        {s.issuedAt ? new Date(s.issuedAt).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ color: 'var(--text-secondary)' }}>
                        {s.lastSeenAt ? new Date(s.lastSeenAt).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {s.status === 'active' ? (
                          <button
                            type="button"
                            className="btn btn-sm btn-danger"
                            onClick={() => setRevokeTarget(s)}
                          >
                            Revoke
                          </button>
                        ) : (
                          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {s.revokeReason ? `Revoked (${s.revokeReason})` : 'Inactive'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No active sessions found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Revocation Modal */}
      <Modal
        isOpen={!!revokeTarget}
        title={revokeTarget === 'ALL' ? 'Revoke All Active Sessions' : 'Revoke Session'}
        confirmText={revokeTarget === 'ALL' ? 'Revoke All Sessions' : 'Revoke Session'}
        isDanger={true}
        loading={actionLoading}
        onConfirm={handleConfirmRevoke}
        onCancel={() => setRevokeTarget(null)}
      >
        {revokeTarget === 'ALL' ? (
          <div>
            Are you sure you want to <strong>revoke all active sessions</strong> for your account?
            <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
              All browser tabs, mobile apps, and extensions will be immediately disconnected.
            </div>
          </div>
        ) : (
          <div>
            Are you sure you want to revoke session{' '}
            <strong>{revokeTarget?.jti ? `${revokeTarget.jti.slice(0, 8)}…` : ''}</strong>?
            <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
              Any client using this token will be immediately rejected.
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
