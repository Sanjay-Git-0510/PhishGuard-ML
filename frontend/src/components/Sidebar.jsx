import React from 'react';
import { 
  ShieldCheck, 
  Radar, 
  Activity, 
  Cpu, 
  Layers, 
  Server,
  Mail,
  Info,
} from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, health }) {
  const navItems = [
    { id: 'scanner', label: 'URL Threat Scanner', icon: Radar, badge: 'URL' },
    { id: 'message', label: 'Message Analysis', icon: Mail, badge: 'NEW' },
    { id: 'heatmap', label: 'Vulnerability Matrix', icon: Layers },
    { id: 'logs', label: 'Ingestion Feed & Audit', icon: Activity },
    { id: 'model', label: 'Model Intelligence', icon: Cpu },
    { id: 'batch', label: 'Batch Static Analysis', icon: Server },
    { id: 'about', label: 'About / How It Works', icon: Info },
  ];

  return (
    <aside className="soc-sidebar">
      <div>
        <div className="sidebar-brand">
          <div className="brand-icon-box">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="brand-title">TRUSTLENS</div>
            <span className="brand-badge">v2.0 · TRUSTLENS</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Operations Console</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                className={`nav-item ${isActive ? 'active' : ''}`}
                onClick={() => onSelectTab(item.id)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Icon size={16} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="sidebar-tab-badge">{item.badge}</span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="sidebar-footer">
        <div className="footer-status-row">
          <span>STATIC ENGINE:</span>
          <span style={{ color: 'var(--terminal-green)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="status-indicator-dot"></span>
            ACTIVE
          </span>
        </div>
        <div className="footer-status-row">
          <span>SAFETY PROTOCOL:</span>
          <span style={{ color: 'var(--electric-blue)' }}>NO-FETCH / AIRGAP</span>
        </div>
        <div className="footer-status-row">
          <span>DATABASE:</span>
          <span style={{ color: health?.database_status === 'connected' ? 'var(--terminal-green)' : 'var(--vibrant-amber)' }}>
            {health?.database_status || 'LOCAL'}
          </span>
        </div>
      </div>
    </aside>
  );
}
