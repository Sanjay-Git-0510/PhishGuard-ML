import React from 'react';
import { ShieldCheck, Cpu, Database, Activity } from 'lucide-react';

export default function HeaderTelemetry({ modelInfo, health }) {
  const modelName = modelInfo?.selected_model || 'Random Forest';
  const recall = modelInfo?.best_metrics?.recall ? `${(modelInfo.best_metrics.recall * 100).toFixed(0)}%` : '100%';
  const roc = modelInfo?.best_metrics?.roc_auc ? modelInfo.best_metrics.roc_auc.toFixed(3) : '1.000';
  const totalSamples = modelInfo?.dataset_samples || 348;
  const isOnline = health?.status === 'healthy';

  return (
    <header className="top-telemetry-bar">
      <div className="telemetry-left">
        <div className="page-headline-group">
          <h1>THREAT INTELLIGENCE FEED</h1>
          <p>Real-time Static URL Phishing Classification & Lexical Telemetry</p>
        </div>
      </div>

      <div className="telemetry-stats-group">
        <div className="telemetry-stat-card">
          <div className="stat-icon-wrapper" style={{ color: isOnline ? 'var(--terminal-green)' : 'var(--vibrant-amber)' }}>
            <ShieldCheck size={16} />
          </div>
          <div className="stat-content">
            <span className="stat-title">Engine State</span>
            <span className="stat-value" style={{ color: isOnline ? 'var(--terminal-green)' : 'var(--vibrant-amber)' }}>
              {isOnline ? 'Active Guard' : 'Standby'}
            </span>
          </div>
        </div>
        <div className="telemetry-stat-card">
          <div className="stat-icon-wrapper">
            <Cpu size={16} />
          </div>
          <div className="stat-content">
            <span className="stat-title">Engine Core</span>
            <span className="stat-value">{modelName}</span>
          </div>
        </div>

        <div className="telemetry-stat-card">
          <div className="stat-icon-wrapper" style={{ color: 'var(--terminal-green)' }}>
            <Activity size={16} />
          </div>
          <div className="stat-content">
            <span className="stat-title">ROC-AUC / Match</span>
            <span className="stat-value" style={{ color: 'var(--terminal-green)' }}>{roc} ({recall} Rec)</span>
          </div>
        </div>

        <div className="telemetry-stat-card">
          <div className="stat-icon-wrapper" style={{ color: 'var(--electric-blue)' }}>
            <Database size={16} />
          </div>
          <div className="stat-content">
            <span className="stat-title">Verified Signatures</span>
            <span className="stat-value">{totalSamples} Samples</span>
          </div>
        </div>
      </div>
    </header>
  );
}
