import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Info } from 'lucide-react';

const RISK_CONFIG = {
  high: {
    color: 'var(--cyber-crimson)',
    dim: 'rgba(255, 51, 102, 0.08)',
    border: 'rgba(255, 51, 102, 0.4)',
    icon: ShieldAlert,
    label: 'HIGH RISK',
    tagClass: 'high',
  },
  medium: {
    color: 'var(--vibrant-amber)',
    dim: 'rgba(255, 170, 0, 0.08)',
    border: 'rgba(255, 170, 0, 0.4)',
    icon: AlertTriangle,
    label: 'MEDIUM RISK',
    tagClass: 'medium',
  },
  low: {
    color: 'var(--terminal-green)',
    dim: 'rgba(0, 255, 102, 0.06)',
    border: 'rgba(0, 255, 102, 0.3)',
    icon: ShieldCheck,
    label: 'LOW RISK',
    tagClass: 'low',
  },
};

export default function RiskCard({ riskAssessment, mlClassification, channel, language }) {
  if (!riskAssessment) return null;

  const level = riskAssessment.risk_level || 'low';
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.low;
  const Icon = cfg.icon;

  return (
    <div style={{
      background: cfg.dim,
      border: `1px solid ${cfg.border}`,
      borderRadius: '8px',
      padding: '20px 24px',
      display: 'flex',
      flexDirection: 'column',
      gap: '16px',
    }}>
      {/* Header Row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '52px', height: '52px', borderRadius: '10px',
            background: `rgba(${level === 'high' ? '255,51,102' : level === 'medium' ? '255,170,0' : '0,255,102'}, 0.12)`,
            border: `1px solid ${cfg.color}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Icon size={26} style={{ color: cfg.color }} />
          </div>
          <div>
            <div style={{ fontSize: '22px', fontWeight: '800', letterSpacing: '1px', color: cfg.color }}>
              {cfg.label}
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>
              {riskAssessment.explanation}
            </div>
            {(channel || language) && (
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
                {channel ? `Channel: ${channel.toUpperCase()}` : ''}
                {channel && language ? ' · ' : ''}
                {language ? `Language: ${language}` : ''}
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', alignItems: 'flex-end', flexShrink: 0 }}>
          <span className={`risk-tag ${cfg.tagClass}`}>
            RISK: {level.toUpperCase()}
          </span>
          {mlClassification && (
            <span style={{
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: mlClassification.label === 'suspicious' ? 'var(--cyber-crimson)' : 'var(--terminal-green)',
              background: mlClassification.label === 'suspicious' ? 'rgba(255,51,102,0.1)' : 'rgba(0,255,102,0.1)',
              padding: '2px 8px', borderRadius: '4px',
            }}>
              ML: {mlClassification.label?.toUpperCase()} ({(mlClassification.suspicious_probability * 100).toFixed(1)}%)
            </span>
          )}
        </div>
      </div>

      {/* Contributing Factors */}
      {riskAssessment.contributing_factors && riskAssessment.contributing_factors.length > 0 && (
        <div>
          <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.5px', marginBottom: '8px' }}>
            Contributing Factors
          </div>
          <ul style={{ display: 'flex', flexDirection: 'column', gap: '6px', listStyle: 'none', padding: 0, margin: 0 }}>
            {riskAssessment.contributing_factors.map((factor, i) => (
              <li key={i} style={{ display: 'flex', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                <span style={{ color: cfg.color, flexShrink: 0, fontWeight: '700' }}>▸</span>
                <span>{factor}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Rules & ML Model Note */}
      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
        {riskAssessment.triggered_rules && riskAssessment.triggered_rules.length > 0 && (
          <div style={{
            background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
            borderRadius: '6px', padding: '8px 14px',
            fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
          }}>
            Rules triggered: {riskAssessment.triggered_rules.join(', ')}
          </div>
        )}
        {mlClassification && !mlClassification.model_available && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '6px',
            background: 'rgba(255,170,0,0.06)', border: '1px solid rgba(255,170,0,0.2)',
            borderRadius: '6px', padding: '8px 12px',
            fontSize: '11px', color: 'var(--vibrant-amber)',
          }}>
            <Info size={12} />
            ML model using rule-based fallback
          </div>
        )}
      </div>

      {/* Risk Note */}
      <div style={{
        background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)',
        borderRadius: '6px', padding: '10px 14px',
        fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic',
      }}>
        {riskAssessment.risk_note}
      </div>
    </div>
  );
}

