import React, { useState } from 'react';
import { api } from '../services/api.js';
import { useAuth } from '../context/AuthContext.jsx';

export function LoginPage() {
  const { loginWithToken } = useAuth();
  const [email, setEmail] = useState('demo@vaultbase.io');
  const [password, setPassword] = useState('demo1234');
  const [mfaState, setMfaState] = useState(null); // { mfaToken, requiredFactors, step: 'OTP' }
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.login(email, password);
      if (res.success && res.data) {
        const { mfaToken, requiredFactors } = res.data;

        if (requiredFactors.includes('otp')) {
          // Trigger OTP dispatch
          await api.sendOtp(mfaToken);
          setMfaState({ mfaToken, requiredFactors, step: 'OTP' });
        } else {
          // Issue tokens directly
          const tokenRes = await api.issueTokens(mfaToken);
          if (tokenRes.success && tokenRes.data?.accessToken) {
            await loginWithToken(tokenRes.data.accessToken);
          }
        }
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleOtpSubmit(e) {
    e.preventDefault();
    if (!mfaState || !otp) return;
    setError(null);
    setLoading(true);

    try {
      const verifyRes = await api.verifyOtp(mfaState.mfaToken, otp);
      if (verifyRes.success) {
        const tokenRes = await api.issueTokens(mfaState.mfaToken);
        if (tokenRes.success && tokenRes.data?.accessToken) {
          await loginWithToken(tokenRes.data.accessToken);
        }
      }
    } catch (err) {
      setError(err.message || 'OTP verification failed');
    } finally {
      setLoading(false);
    }
  }

  function setDemoCredentials(demoEmail, demoPw) {
    setEmail(demoEmail);
    setPassword(demoPw);
    setMfaState(null);
    setError(null);
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <div style={{ fontSize: 36, marginBottom: 8 }}>🛡️</div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>VaultBase Security Center</h1>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
            Sign in to inspect and control your authenticated security posture
          </p>
        </div>

        {error && (
          <div
            style={{
              background: 'var(--status-critical-bg)',
              border: '1px solid var(--status-critical-border)',
              color: 'var(--status-critical)',
              padding: 10,
              borderRadius: 8,
              fontSize: 13,
              marginBottom: 16,
            }}
          >
            {error}
          </div>
        )}

        {!mfaState ? (
          <form onSubmit={handlePasswordSubmit}>
            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                className="form-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@vaultbase.io"
                required
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: 8 }} disabled={loading}>
              {loading ? 'Authenticating...' : 'Sign In to Security Center'}
            </button>

            <div style={{ marginTop: 20, borderTop: '1px solid var(--border-color)', paddingTop: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>Fast Demo Accounts:</div>
              <div className="demo-account-chips">
                <button type="button" className="chip" onClick={() => setDemoCredentials('demo@vaultbase.io', 'demo1234')}>
                  demo@vaultbase.io
                </button>
                <button type="button" className="chip" onClick={() => setDemoCredentials('alice@example.com', 'alice1234')}>
                  alice@example.com
                </button>
                <button type="button" className="chip" onClick={() => setDemoCredentials('bob@example.com', 'bob1234')}>
                  bob@example.com
                </button>
                <button type="button" className="chip" onClick={() => setDemoCredentials('admin@vaultbase.io', 'admin1234')}>
                  admin@vaultbase.io
                </button>
              </div>
            </div>
          </form>
        ) : (
          <form onSubmit={handleOtpSubmit}>
            <div style={{ textAlign: 'center', marginBottom: 16 }}>
              <div style={{ fontSize: 24, marginBottom: 6 }}>📧</div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>Enter Verification Code</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                A 6-digit security code was dispatched to your email
              </div>
            </div>

            <div className="form-group">
              <input
                type="text"
                className="form-input"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                placeholder="123456"
                maxLength={6}
                style={{ textAlign: 'center', fontSize: 20, letterSpacing: '0.2em' }}
                autoFocus
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Verifying Code...' : 'Complete Sign In'}
            </button>

            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: '100%', marginTop: 8 }}
              onClick={() => setMfaState(null)}
            >
              ← Back
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
