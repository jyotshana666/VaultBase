import React from 'react';

export function Sidebar({ currentTab, onSelectTab }) {
  const navItems = [
    { id: 'overview', label: 'Security Overview', icon: '📊' },
    { id: 'devices', label: 'Trusted Devices', icon: '💻' },
    { id: 'sessions', label: 'Active Sessions', icon: '🔑' },
    { id: 'audit-logs', label: 'Login History', icon: '📜' },
    { id: 'risk-events', label: 'Risk Events & Signals', icon: '⚡' },
    { id: 'alerts', label: 'Security Alerts', icon: '🚨' },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-item ${currentTab === item.id ? 'active' : ''}`}
            onClick={() => onSelectTab(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </div>

      <div style={{ padding: '16px', fontSize: 12, color: 'var(--text-muted)' }}>
        <div>VaultBase Core v1.0.0</div>
        <div>Phase 9: Security Center</div>
      </div>
    </aside>
  );
}
