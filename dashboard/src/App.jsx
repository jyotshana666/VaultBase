import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import { SocketProvider } from './context/SocketContext.jsx';
import { Navbar } from './components/Navbar.jsx';
import { Sidebar } from './components/Sidebar.jsx';
import { SecurityAlertBanner } from './components/SecurityAlertBanner.jsx';
import { LoginPage } from './pages/LoginPage.jsx';
import { SecurityOverview } from './pages/SecurityOverview.jsx';
import { DevicesPage } from './pages/DevicesPage.jsx';
import { SessionsPage } from './pages/SessionsPage.jsx';
import { LoginHistoryPage } from './pages/LoginHistoryPage.jsx';
import { RiskEventsPage } from './pages/RiskEventsPage.jsx';
import { SecurityAlertsPage } from './pages/SecurityAlertsPage.jsx';

function DashboardLayout() {
  const { isAuthenticated, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState('overview');

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        Loading VaultBase Security Center...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <SocketProvider>
      <div className="app-container">
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />
        <div className="main-content">
          <Navbar />
          <main className="page-body">
            <SecurityAlertBanner />
            {currentTab === 'overview' && <SecurityOverview onNavigate={setCurrentTab} />}
            {currentTab === 'devices' && <DevicesPage />}
            {currentTab === 'sessions' && <SessionsPage />}
            {currentTab === 'audit-logs' && <LoginHistoryPage />}
            {currentTab === 'risk-events' && <RiskEventsPage />}
            {currentTab === 'alerts' && <SecurityAlertsPage />}
          </main>
        </div>
      </div>
    </SocketProvider>
  );
}

export function App() {
  return (
    <AuthProvider>
      <DashboardLayout />
    </AuthProvider>
  );
}
