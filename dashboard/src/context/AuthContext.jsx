import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../services/api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [sessionRecord, setSessionRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function checkAuth() {
    const token = api.getStoredToken();
    if (!token) {
      setUser(null);
      setSessionRecord(null);
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      const res = await api.getSession();
      if (res.success && res.data) {
        setUser(res.data.user);
        setSessionRecord(res.data.session);
        setError(null);
      } else {
        setUser(null);
        setSessionRecord(null);
      }
    } catch (err) {
      console.warn('[AuthContext] Session validation failed:', err.message);
      setUser(null);
      setSessionRecord(null);
      api.setStoredToken(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    checkAuth();

    function handleUnauthorized(e) {
      setUser(null);
      setSessionRecord(null);
      api.setStoredToken(null);
      setError(e.detail?.message || 'Session expired or revoked');
    }

    window.addEventListener('vaultbase:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('vaultbase:unauthorized', handleUnauthorized);
  }, []);

  async function loginWithToken(token) {
    api.setStoredToken(token);
    await checkAuth();
  }

  async function logout() {
    try {
      await api.logout();
    } catch (e) {
      console.error('[AuthContext] Logout error:', e);
    } finally {
      setUser(null);
      setSessionRecord(null);
      api.setStoredToken(null);
    }
  }

  const value = {
    user,
    sessionRecord,
    loading,
    error,
    isAuthenticated: !!user,
    loginWithToken,
    logout,
    refreshSession: checkAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
