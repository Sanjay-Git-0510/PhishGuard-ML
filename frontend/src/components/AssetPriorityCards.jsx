import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2, Terminal } from 'lucide-react';

export default function AssetPriorityCards({ result }) {
  const isPhish = result?.prediction === 'phishing';

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <div className="panel-header-left">
          <Terminal size={16} style={{ color: 'var(--electric-blue)' }} />
          <span className="panel-title">Asset & Threat Vector Priority Triage</span>
        </div>
        <span className="panel-badge">SOC Level-1 & Level-2 Analysis</span>
      </div>

      <div className="soc-panel-body">
        <div className="asset-cards-grid">
          <div className="asset-card">
            <div className="asset-card-header">
              <span className="asset-card-title">
                <ShieldAlert size={16} style={{ color: isPhish ? 'var(--cyber-crimson)' : 'var(--text-muted)' }} />
                P1: Credential Interception
              </span>
              <span className={`risk-tag ${isPhish ? 'high' : 'low'}`}>
                {isPhish ? 'CRITICAL' : 'NOMINAL'}
              </span>
            </div>
            <p className="asset-card-desc">
              {isPhish 
                ? 'Monitored payload shows targeted lure keywords combined with structural diversion to harvest credentials.'
                : 'No anomalous credential harvesting patterns detected on destination structure.'}
            </p>
          </div>

          <div className="asset-card">
            <div className="asset-card-header">
              <span className="asset-card-title">
                <AlertTriangle size={16} style={{ color: 'var(--vibrant-amber)' }} />
                P2: Brand & Domain Impersonation
              </span>
              <span className="risk-tag medium">
                MONITORED
              </span>
            </div>
            <p className="asset-card-desc">
              Heuristic checks evaluate multi-level subdomains and brand keyword combinations targeting corporate identity trust.
            </p>
          </div>

          <div className="asset-card">
            <div className="asset-card-header">
              <span className="asset-card-title">
                <CheckCircle2 size={16} style={{ color: 'var(--terminal-green)' }} />
                P3: Air-Gapped Static Assurance
              </span>
              <span className="risk-tag low">
                ENFORCED
              </span>
            </div>
            <p className="asset-card-desc">
              Zero outbound network interaction. Submitted URLs are never rendered, downloaded, or contacted by this engine.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
