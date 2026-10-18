// VaultBase Dashboard API Client
const API_BASE = window.__VAULTBASE_API_URL || 'http://localhost:5000';

function getStoredToken() {
  return localStorage.getItem('vaultbase_token') || sessionStorage.getItem('vaultbase_token') || '';
}

function setStoredToken(token, persist = true) {
  if (token) {
    if (persist) {
      localStorage.setItem('vaultbase_token', token);
    } else {
      sessionStorage.setItem('vaultbase_token', token);
    }
  } else {
    localStorage.removeItem('vaultbase_token');
    sessionStorage.removeItem('vaultbase_token');
  }
}

async function request(endpoint, options = {}) {
  const token = options.token || getStoredToken();
  const headers = {
    'Content-Type': 'application/json',
    'X-Device-Fingerprint': options.fingerprint || localStorage.getItem('vaultbase_dashboard_fp') || 'dashboard-web-client-fp',
    ...(options.headers || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, config);
    const data = await res.json().catch(() => ({ success: false, message: 'Invalid JSON response' }));

    if (res.status === 401) {
      // Auto clean-up if session was revoked / expired
      if (data.code === 'REVOKED-401' || data.code === 'HIJACK-401' || data.code === 'BLACK-401') {
        window.dispatchEvent(new CustomEvent('vaultbase:unauthorized', { detail: data }));
      }
    }

    if (!res.ok) {
      const error = new Error(data.message || `HTTP error ${res.status}`);
      error.status = res.status;
      error.data = data;
      throw error;
    }

    return data;
  } catch (err) {
    if (!err.status && err.name === 'TypeError') {
      err.message = 'Unable to connect to VaultBase backend server';
    }
    throw err;
  }
}

export const api = {
  getStoredToken,
  setStoredToken,

  // Auth & Session
  async login(email, password, fingerprint = 'dashboard-web-client-fp') {
    return request('/auth/login', {
      method: 'POST',
      body: { email, password },
      fingerprint,
    });
  },

  async sendOtp(mfaToken) {
    return request('/auth/send-otp', {
      method: 'POST',
      body: { mfaToken },
    });
  },

  async verifyOtp(mfaToken, otp) {
    return request('/auth/verify-otp', {
      method: 'POST',
      body: { mfaToken, otp },
    });
  },

  async issueTokens(mfaToken) {
    return request('/auth/issue-tokens', {
      method: 'POST',
      body: { mfaToken },
    });
  },

  async getSession() {
    return request('/auth/session');
  },

  async logout() {
    try {
      await request('/auth/logout', { method: 'POST' });
    } finally {
      setStoredToken(null);
    }
  },

  // Dashboard Aggregations
  async getOverview() {
    return request('/auth/overview');
  },

  async getAuditLogs() {
    return request('/auth/audit-logs');
  },

  async getRiskEvents() {
    return request('/auth/risk-events');
  },

  // Devices Management
  async getDevices() {
    return request('/auth/devices');
  },

  async revokeDevice(target) {
    return request('/auth/devices/revoke', {
      method: 'POST',
      body: { fingerprint: target, deviceId: target },
    });
  },

  // Sessions Management
  async getSessions() {
    return request('/auth/sessions');
  },

  async revokeSession(jti) {
    return request('/auth/sessions/revoke', {
      method: 'POST',
      body: { jti },
    });
  },

  async revokeAllSessions() {
    return request('/auth/sessions/revoke-all', {
      method: 'POST',
    });
  },
};
