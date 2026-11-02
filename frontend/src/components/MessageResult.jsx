import React, { useState } from 'react';
import {
  Link2, ShieldOff, CheckCircle, AlertTriangle, ChevronDown, ChevronUp,
  Shield, ShieldCheck, ShieldAlert, MessageSquare, Cpu, Info,
} from 'lucide-react';
import RiskCard from './RiskCard';
import EvidenceCard from './EvidenceCard';
import IdentityAnalysis from './IdentityAnalysis';
import FeedbackForm from './FeedbackForm';

// ─── Social Engineering Section ──────────────────────────────────────
const SE_CATEGORIES = [
  { key: 'urgency', label: 'Urgency & Pressure', color: 'var(--vibrant-amber)' },
  { key: 'fear', label: 'Fear & Threat', color: 'var(--cyber-crimson)' },
  { key: 'credential_request', label: 'Credential Harvesting', color: 'var(--cyber-crimson)' },
  { key: 'financial', label: 'Financial Manipulation', color: 'var(--vibrant-amber)' },
  { key: 'impersonation', label: 'Impersonation', color: 'var(--cyber-crimson)' },
];

function SeCategoryRow({ category, signals }) {
  const [open, setOpen] = useState(false);
  if (!signals || signals.length === 0) return null;

  return (
    <div style={{
      border: '1px solid var(--border-subtle)', borderRadius: '6px', overflow: 'hidden',
    }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '10px 14px', background: 'rgba(255,255,255,0.02)', border: 'none',
          cursor: 'pointer', color: 'var(--text-primary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: category.color, flexShrink: 0, display: 'inline-block',
          }} />
          <span style={{ fontSize: '13px', fontWeight: '600' }}>{category.label}</span>
          <span style={{
            fontSize: '10px', background: `${category.color}22`,
            color: category.color, padding: '1px 6px', borderRadius: '3px', fontWeight: '700',
          }}>
            {signals.length} signal{signals.length > 1 ? 's' : ''}
          </span>
        </div>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>

      {open && (
        <div style={{ padding: '10px 14px', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {signals.map((sig, i) => (
            <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {sig.evidence && (
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: '11px',
                  background: 'rgba(0,0,0,0.3)', borderRadius: '4px', padding: '6px 10px',
                  color: 'var(--text-secondary)', wordBreak: 'break-all', whiteSpace: 'pre-wrap',
                }}>
                  {sig.evidence}
                </div>
              )}
              {sig.explanation && (
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{sig.explanation}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SocialEngineeringSection({ seResults }) {
  if (!seResults) return null;

  const hasAny = SE_CATEGORIES.some(cat => {
    const s = seResults[cat.key];
    return s && ((s.signals && s.signals.length > 0) || (Array.isArray(s) && s.length > 0));
  });

  if (!hasAny) {
    return (
      <div className="soc-panel">
        <div className="soc-panel-header">Social Engineering Indicators</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 0', color: 'var(--terminal-green)', fontSize: '13px' }}>
          <CheckCircle size={16} />
          No social engineering patterns detected in this message.
        </div>
      </div>
    );
  }

  // Flatten severity counts
  let total = 0;
  SE_CATEGORIES.forEach(cat => {
    const s = seResults[cat.key];
    if (s?.signals) total += s.signals.length;
    else if (Array.isArray(s)) total += s.length;
  });

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="soc-panel-header">
        <span>Social Engineering Indicators</span>
        <span style={{ fontSize: '11px', color: 'var(--vibrant-amber)' }}>
          {total} signal{total !== 1 ? 's' : ''} detected
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {SE_CATEGORIES.map(cat => {
          const s = seResults[cat.key];
          const signals = s?.signals || (Array.isArray(s) ? s : []);
          return (
            <SeCategoryRow key={cat.key} category={cat} signals={signals} />
          );
        })}
      </div>
    </div>
  );
}

// ─── URL Analysis Section ────────────────────────────────────────────
function UrlAnalysisSection({ urlAnalysis }) {
  if (!urlAnalysis) return null;
  // The backend returns results[] for per-URL details, urls_found[] for raw URLs
  const urls = urlAnalysis.results || urlAnalysis.analyzed_urls || urlAnalysis.urls || [];
  const urlCount = urlAnalysis.url_count ?? urls.length;

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="soc-panel-header">
        <span>Embedded URL Analysis</span>
        <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {urlCount} URL{urlCount !== 1 ? 's' : ''} found
        </span>
      </div>

      {urls.length === 0 && (
        <div style={{ fontSize: '13px', color: 'var(--text-muted)', padding: '4px 0' }}>
          No URLs detected in message body.
        </div>
      )}

      {urls.map((u, i) => {
        // u has: url, prediction (string), probability (float), risk_level, reasons, metadata
        const isPhishing = u.prediction === 'phishing';
        const flagColor = isPhishing ? 'var(--cyber-crimson)' : 'var(--terminal-green)';
        const confidence = u.probability ?? null;

        return (
          <div key={i} style={{
            background: 'rgba(0,0,0,0.25)', border: `1px solid ${isPhishing ? 'rgba(255,51,102,0.3)' : 'var(--border-subtle)'}`,
            borderRadius: '6px', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '8px',
          }}>
            {/* URL as plain text — NOT a clickable link (security requirement) */}
            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <Link2 size={13} style={{ color: 'var(--text-muted)', marginTop: '2px', flexShrink: 0 }} />
              <span
                className="url-plain-text"
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: '11px',
                  color: 'var(--text-secondary)', wordBreak: 'break-all',
                  userSelect: 'text',
                }}
              >
                {u.url}
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              {u.prediction && (
                <span style={{
                  fontSize: '10px', fontWeight: '700', letterSpacing: '0.5px',
                  color: flagColor, background: `${flagColor}18`,
                  border: `1px solid ${flagColor}55`, padding: '2px 8px', borderRadius: '4px',
                }}>
                  {u.prediction.toUpperCase()}
                </span>
              )}
              {confidence !== null && (
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Confidence: {(confidence * 100).toFixed(1)}%
                </span>
              )}
              {u.metadata?.is_shortener && (
                <span style={{ fontSize: '10px', color: 'var(--vibrant-amber)', background: 'rgba(255,170,0,0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                  URL SHORTENER
                </span>
              )}
            </div>

            {u.reasons && u.reasons.length > 0 && (
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '3px' }}>
                {u.reasons.map((r, j) => (
                  <li key={j} style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', gap: '6px' }}>
                    <span style={{ color: 'var(--vibrant-amber)' }}>▸</span>{r}
                  </li>
                ))}
              </ul>
            )}          </div>
        );
      })}

      <div style={{
        fontSize: '10px', color: 'var(--text-muted)', fontStyle: 'italic',
        borderTop: '1px solid var(--border-subtle)', paddingTop: '8px',
      }}>
        ⓘ URLs are displayed as plain text. TRUSTLENS does not open or resolve any links.
      </div>
    </div>
  );
}

// ─── ML Classification Section ───────────────────────────────────────
function MlClassificationSection({ mlClassification }) {
  if (!mlClassification) return null;
  const isSus = mlClassification.label === 'suspicious';
  const pct = mlClassification.suspicious_probability != null
    ? (mlClassification.suspicious_probability * 100).toFixed(1)
    : null;

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="soc-panel-header">
        <span>ML Message Classification</span>
        <Cpu size={14} style={{ color: 'var(--electric-blue)' }} />
      </div>

      <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          background: isSus ? 'rgba(255,51,102,0.08)' : 'rgba(0,255,102,0.06)',
          border: `1px solid ${isSus ? 'rgba(255,51,102,0.3)' : 'rgba(0,255,102,0.25)'}`,
          borderRadius: '8px', padding: '12px 18px',
        }}>
          {isSus
            ? <ShieldAlert size={22} style={{ color: 'var(--cyber-crimson)' }} />
            : <ShieldCheck size={22} style={{ color: 'var(--terminal-green)' }} />
          }
          <div>
            <div style={{
              fontSize: '16px', fontWeight: '800', letterSpacing: '0.5px',
              color: isSus ? 'var(--cyber-crimson)' : 'var(--terminal-green)',
            }}>
              {mlClassification.label?.toUpperCase() || 'UNKNOWN'}
            </div>
            {pct !== null && (
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Suspicious probability: {pct}%
              </div>
            )}
          </div>
        </div>

        {!mlClassification.model_available && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px',
            color: 'var(--vibrant-amber)', background: 'rgba(255,170,0,0.06)',
            border: '1px solid rgba(255,170,0,0.2)', borderRadius: '5px', padding: '8px 12px',
          }}>
            <Info size={12} />
            ML model using rule-based fallback
          </div>
        )}
      </div>

      {mlClassification.model_name && (
        <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Model: {mlClassification.model_name}
          {mlClassification.model_version && ` · v${mlClassification.model_version}`}
        </div>
      )}
    </div>
  );
}

// ─── Recommendations Section ──────────────────────────────────────────
function RecommendationsSection({ recommendations }) {
  if (!recommendations || recommendations.length === 0) return null;

  const iconMap = [
    '🔒', '📞', '🌐', '⛔', '📋', '🔑', '💳', '🛡️', '✉️', '📱',
  ];

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="soc-panel-header">
        <span>Safe Verification Recommendations</span>
        <Shield size={14} style={{ color: 'var(--electric-blue)' }} />
      </div>
      <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {recommendations.map((rec, i) => (
          <li
            key={i}
            className="recommendation-item"
            style={{
              display: 'flex', gap: '12px', alignItems: 'flex-start',
              padding: '10px 12px',
              background: 'rgba(30,144,255,0.04)', border: '1px solid rgba(30,144,255,0.12)',
              borderRadius: '6px',
            }}
          >
            <span style={{ fontSize: '18px', flexShrink: 0, marginTop: '-1px' }}>
              {iconMap[i % iconMap.length]}
            </span>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              {rec}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

// ─── Privacy Notice ───────────────────────────────────────────────────
function PrivacyNotice() {
  return (
    <div style={{
      display: 'flex', gap: '8px', alignItems: 'flex-start',
      background: 'rgba(30,144,255,0.05)', border: '1px solid rgba(30,144,255,0.15)',
      borderRadius: '6px', padding: '10px 14px',
      fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5',
    }}>
      <ShieldCheck size={14} style={{ color: 'var(--electric-blue)', flexShrink: 0, marginTop: '1px' }} />
      TRUSTLENS performs static security analysis. It does not open submitted links,
      send messages or perform actions on your behalf. Original message content is not stored.
    </div>
  );
}

// ─── Main MessageResult ───────────────────────────────────────────────
function KnownChannelGuidance() {
  return (
    <div
      className="soc-panel"
      style={{
        border: '1px solid rgba(30,144,255,0.35)',
        background: 'rgba(30,144,255,0.07)',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      <div className="soc-panel-header">
        <span>Verify through a known channel</span>
        <Shield size={14} style={{ color: 'var(--electric-blue)' }} />
      </div>
      <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
        Before you click, reply, pay, or share an OTP, confirm the request using a channel
        you already trust: the official app, a website you type yourself, or a phone number
        from your bank card or a previous genuine statement. Do not use contact details
        from this message.
      </p>
    </div>
  );
}

export default function MessageResult({ result, channel, sourcePayload, onReanalyze }) {
  if (!result) return null;

  const correction = result.user_correction_applied;

  return (
    <div
      className="message-result-container"
      style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}
    >
      <PrivacyNotice />

      {correction && (
        <div style={{
          display: 'flex', gap: '8px', alignItems: 'flex-start',
          background: 'rgba(0,255,102,0.06)', border: '1px solid rgba(0,255,102,0.25)',
          borderRadius: '6px', padding: '10px 14px',
          fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5,
        }}>
          <CheckCircle size={14} style={{ color: 'var(--terminal-green)', flexShrink: 0, marginTop: '1px' }} />
          This analysis includes a previous user challenge
          ({correction === 'benign' ? 'marked legitimate / benign' : 'marked still suspicious'}).
          The message classifier was retrained with that label.
        </div>
      )}

      {/* 1. Overall Risk */}
      <RiskCard
        riskAssessment={result.risk_assessment}
        mlClassification={result.ml_classification}
        channel={channel}
        language={result.language || result.detected_language}
      />

      <KnownChannelGuidance />

      {/* 2. ML Classification detail */}
      <MlClassificationSection mlClassification={result.ml_classification} />

      {/* 3. URL Analysis */}
      <UrlAnalysisSection urlAnalysis={result.url_analysis} />

      {/* 4. Identity Analysis */}
      <IdentityAnalysis identityAnalysis={result.identity_analysis} channel={channel} />

      {/* 5. Social Engineering */}
      <SocialEngineeringSection seResults={result.social_engineering} />

      {/* 6. Evidence */}
      <EvidenceCard evidence={result.evidence} />

      {/* 7. Recommendations */}
      <RecommendationsSection recommendations={result.recommendations} />

      {/* 8. False-positive challenge */}
      <FeedbackForm
        analysisId={result.analysis_id}
        originalRiskLevel={result.risk_assessment?.risk_level}
        channel={channel || result.channel}
        language={result.language}
        messageText={sourcePayload?.message}
        onReanalyze={onReanalyze}
      />
    </div>
  );
}
