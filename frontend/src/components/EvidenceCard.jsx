import React, { useState } from 'react';
import { AlertTriangle, AlertCircle, Info, ChevronDown, ChevronUp } from 'lucide-react';

const SEVERITY_CONFIG = {
  high: {
    color: 'var(--cyber-crimson)',
    bg: 'rgba(255,51,102,0.06)',
    border: 'rgba(255,51,102,0.3)',
    icon: AlertCircle,
    label: 'HIGH',
  },
  medium: {
    color: 'var(--vibrant-amber)',
    bg: 'rgba(255,170,0,0.06)',
    border: 'rgba(255,170,0,0.25)',
    icon: AlertTriangle,
    label: 'MEDIUM',
  },
  low: {
    color: 'var(--terminal-green)',
    bg: 'rgba(0,255,102,0.04)',
    border: 'rgba(0,255,102,0.2)',
    icon: Info,
    label: 'LOW',
  },
};

function EvidenceItem({ item }) {
  const [expanded, setExpanded] = useState(true);
  const sev = item.severity || 'medium';
  const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.medium;
  const Icon = cfg.icon;

  return (
    <div
      className={`evidence-item ${sev}`}
      style={{
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderLeft: `3px solid ${cfg.color}`,
        borderRadius: '6px',
        padding: '12px 14px',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      {/* Item header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Icon size={14} style={{ color: cfg.color, flexShrink: 0 }} />
          <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>
            {item.signal || item.signal_type || 'Signal'}
          </span>
          <span
            className="severity-badge"
            style={{
              background: cfg.color,
              color: '#000',
              fontSize: '9px',
              fontWeight: '700',
              padding: '2px 6px',
              borderRadius: '3px',
              letterSpacing: '0.5px',
            }}
          >
            {cfg.label}
          </span>
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          style={{
            background: 'none', border: 'none', color: 'var(--text-muted)',
            cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center',
          }}
          aria-label={expanded ? 'Collapse' : 'Expand'}
        >
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {expanded && (
        <>
          {/* Source badge */}
          {item.source && (
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Source: <span style={{ color: 'var(--electric-blue)' }}>{item.source}</span>
            </div>
          )}

          {/* Evidence quote — plain text, NOT a link */}
          {item.evidence && (
            <div
              className="evidence-quote"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                background: 'rgba(0,0,0,0.35)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '4px',
                padding: '8px 10px',
                color: 'var(--text-secondary)',
                wordBreak: 'break-all',
                whiteSpace: 'pre-wrap',
                userSelect: 'text',
              }}
            >
              {item.evidence}
            </div>
          )}

          {/* Explanation */}
          {item.explanation && (
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              {item.explanation}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default function EvidenceCard({ evidence }) {
  if (!evidence || evidence.length === 0) return null;

  // Sort: high → medium → low
  const PRIORITY = { high: 0, medium: 1, low: 2 };
  const sorted = [...evidence].sort((a, b) =>
    (PRIORITY[a.severity] ?? 1) - (PRIORITY[b.severity] ?? 1)
  );

  const highCount = sorted.filter(e => e.severity === 'high').length;
  const medCount = sorted.filter(e => e.severity === 'medium').length;
  const lowCount = sorted.filter(e => e.severity === 'low').length;

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="soc-panel-header">
        <span>Evidence &amp; Detected Signals</span>
        <div style={{ display: 'flex', gap: '6px' }}>
          {highCount > 0 && (
            <span style={{
              fontSize: '10px', background: 'rgba(255,51,102,0.15)',
              color: 'var(--cyber-crimson)', padding: '2px 8px', borderRadius: '4px', fontWeight: '700',
            }}>
              {highCount} HIGH
            </span>
          )}
          {medCount > 0 && (
            <span style={{
              fontSize: '10px', background: 'rgba(255,170,0,0.15)',
              color: 'var(--vibrant-amber)', padding: '2px 8px', borderRadius: '4px', fontWeight: '700',
            }}>
              {medCount} MEDIUM
            </span>
          )}
          {lowCount > 0 && (
            <span style={{
              fontSize: '10px', background: 'rgba(0,255,102,0.1)',
              color: 'var(--terminal-green)', padding: '2px 8px', borderRadius: '4px', fontWeight: '700',
            }}>
              {lowCount} LOW
            </span>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {sorted.map((item, i) => (
          <EvidenceItem key={i} item={item} />
        ))}
      </div>
    </div>
  );
}

