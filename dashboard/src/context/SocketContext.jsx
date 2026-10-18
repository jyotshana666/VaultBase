import React, { createContext, useContext, useEffect, useState } from 'react';
import { useAuth } from './AuthContext.jsx';
import { api } from '../services/api.js';

const SocketContext = createContext(null);

export function SocketProvider({ children }) {
  const { user, isAuthenticated } = useAuth();
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    if (!isAuthenticated || !user) {
      if (socket) {
        socket.disconnect();
        setSocket(null);
        setConnected(false);
      }
      return;
    }

    const token = api.getStoredToken();
    if (!token) return;

    // Check if io client is available (from socket.io-client or window.io)
    const ioLib = window.io || null;
    if (!ioLib) {
      console.warn('[SocketContext] Socket.io client library not loaded; real-time alerts will poll');
      return;
    }

    const newSocket = ioLib('http://localhost:5000', {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    newSocket.on('connect', () => {
      console.log('[SocketContext] Connected to VaultBase real-time event bus');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('[SocketContext] Disconnected from event bus');
      setConnected(false);
    });

    newSocket.on('security:event', (data) => {
      console.log('[SocketContext] Real-time security event received:', data);
      setAlerts((prev) => [
        {
          id: 'rt-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6),
          event: data.event,
          message: data.reason || `Security Event: ${data.event}`,
          details: data,
          timestamp: data.timestamp || new Date().toISOString(),
          read: false,
        },
        ...prev,
      ]);
    });

    newSocket.on('session:hijack', (data) => {
      setAlerts((prev) => [
        {
          id: 'hijack-' + Date.now(),
          event: 'SESSION_HIJACK_SUSPECTED',
          message: `CRITICAL: Potential session hijack detected! Session has been automatically revoked.`,
          details: data,
          severity: 'CRITICAL',
          timestamp: new Date().toISOString(),
          read: false,
        },
        ...prev,
      ]);
    });

    newSocket.on('session:revoked', (data) => {
      setAlerts((prev) => [
        {
          id: 'revoked-' + Date.now(),
          event: 'SESSION_REVOKED',
          message: `Session ${data.jti ? data.jti.slice(0, 8) + '…' : ''} was revoked (${data.reason || 'user action'}).`,
          details: data,
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          read: false,
        },
        ...prev,
      ]);
    });

    newSocket.on('device:revoked', (data) => {
      setAlerts((prev) => [
        {
          id: 'dev-revoked-' + Date.now(),
          event: 'DEVICE_REVOKED',
          message: `Device trust was revoked. Future access from this device will require elevated authentication.`,
          details: data,
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          read: false,
        },
        ...prev,
      ]);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [isAuthenticated, user?.id]);

  function dismissAlert(id) {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  }

  function clearAllAlerts() {
    setAlerts([]);
  }

  const value = {
    socket,
    connected,
    alerts,
    dismissAlert,
    clearAllAlerts,
  };

  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>;
}

export function useSocket() {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
}
