import React, { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import { Badge } from '../components/Badge.jsx';
import { Modal } from '../components/Modal.jsx';

export function DevicesPage() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [feedback, setFeedback] = useState(null);

  async function fetchDevices() {
    try {
      setLoading(true);
      const res = await api.getDevices();
      if (res.success && res.data) {
        setDevices(res.data.devices || []);
        setError(null);
      }
    } catch (err) {
      setError(err.message || 'Failed to load devices');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchDevices();
  }, []);

  async function handleConfirmRevoke() {
    if (!selectedDevice) return;
    try {
      setActionLoading(true);
      const target = selectedDevice.fingerprint || selectedDevice.id;
      const res = await api.revokeDevice(target);
      if (res.success) {
        setFeedback({ type: 'success', message: `Device "${selectedDevice.deviceName || 'Browser'}" was successfully revoked.` });
        await fetchDevices();
      }
    } catch (err) {
      setFeedback({ type: 'error', message: `Revocation failed: ${err.message}` });
    } finally {
      setActionLoading(false);
      setSelectedDevice(null);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Trusted Devices</h1>
          <p className="page-desc">Manage workstations, mobile devices, and browser instances authorized to access your VaultBase account</p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={fetchDevices} disabled={loading}>
          🔄 Refresh
        </button>
      </div>

      {feedback && (
        <div
          className={`card`}
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
          Loading trusted devices...
        </div>
      ) : error ? (
        <div className="card" style={{ textAlign: 'center', padding: 40, borderColor: 'var(--status-critical-border)' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
          <div style={{ fontWeight: 600, color: 'var(--status-critical)', marginBottom: 8 }}>{error}</div>
          <button type="button" className="btn btn-secondary" onClick={fetchDevices}>
            Retry
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Device Name</th>
                <th>Fingerprint ID</th>
                <th>Trust Status</th>
                <th>Registered At</th>
                <th>Last Seen</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.length > 0 ? (
                devices.map((dev) => (
                  <tr key={dev.id || dev.fingerprint}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontSize: 20 }}>
                          {dev.deviceName?.toLowerCase().includes('mobile') || dev.deviceName?.toLowerCase().includes('phone') ? '📱' : '💻'}
                        </span>
                        <div>
                          <div style={{ fontWeight: 600 }}>{dev.deviceName || 'Verified Browser'}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {dev.isTrusted ? 'Authorized hardware' : 'Untrusted / Revoked'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)' }}>
                      {dev.fingerprint ? `${dev.fingerprint.slice(0, 16)}…` : '—'}
                    </td>
                    <td>
                      <Badge variant={dev.status}>{dev.status}</Badge>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>
                      {dev.registeredAt ? new Date(dev.registeredAt).toLocaleDateString() : '—'}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>
                      {dev.lastSeenAt ? new Date(dev.lastSeenAt).toLocaleString() : '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {dev.status !== 'REVOKED' ? (
                        <button
                          type="button"
                          className="btn btn-sm btn-danger"
                          onClick={() => setSelectedDevice(dev)}
                        >
                          Revoke Trust
                        </button>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Revoked</span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No trusted devices found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Confirmation Modal */}
      <Modal
        isOpen={!!selectedDevice}
        title="Revoke Device Trust"
        confirmText="Revoke Device"
        isDanger={true}
        loading={actionLoading}
        onConfirm={handleConfirmRevoke}
        onCancel={() => setSelectedDevice(null)}
      >
        Are you sure you want to revoke trust for <strong>{selectedDevice?.deviceName || 'this device'}</strong>?
        <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
          Any active sessions on this device will be immediately rejected and future sign-in attempts will require high-tier step-up authentication.
        </div>
      </Modal>
    </div>
  );
}
