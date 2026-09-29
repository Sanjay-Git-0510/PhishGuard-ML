import React from 'react';
import { Activity, RefreshCw } from 'lucide-react';

export default function LogIngestionFeed({ logs, onRefresh, onInspect }) {
  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <div className="panel-header-left">
          <Activity size={16} style={{ color: 'var(--electric-blue)' }} />
          <span className="panel-title">Real-Time Ingestion Logs & Telemetry Audit</span>
        </div>
        <button
          className="preset-chip"
          style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          onClick={onRefresh}
        >
          <RefreshCw size={12} />
          <span>Refresh Feed</span>
        </button>
      </div>

      <div className="soc-panel-body" style={{ padding: '12px' }}>
        {logs && logs.length > 0 ? (
          <div className="log-feed-container">
            {logs.map((log) => {
              const isPhish = log.prediction === 'phishing';
              return (
                <div key={log.id} className="log-entry-row">
                  <span className="log-timestamp">
                    {new Date(log.scanned_at).toLocaleTimeString()}
                  </span>
                  <span className={`risk-tag ${isPhish ? 'high' : 'low'}`} style={{ fontSize: '10px' }}>
                    {log.prediction.toUpperCase()}
                  </span>
                  <span style={{ color: isPhish ? 'var(--cyber-crimson)' : 'var(--terminal-green)' }}>
                    {Math.round(log.probability * 100)}% prob
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', minWidth: 0 }}>
                    <span className="log-url" title={log.url}>
                      {log.url}
                    </span>
                    {onInspect && (
                      <button
                        className="preset-chip"
                        style={{ padding: '2px 6px', fontSize: '10px', flexShrink: 0 }}
                        onClick={() => onInspect(log.url)}
                      >
                        Inspect
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            [FEED IDLE] No historical telemetry events recorded yet. Run a URL scan to ingest static log events.
          </div>
        )}
      </div>
    </div>
  );
}
