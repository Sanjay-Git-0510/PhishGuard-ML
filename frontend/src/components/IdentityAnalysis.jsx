import React from 'react';
import { User, Mail, Globe, Smartphone, CheckCircle, XCircle, AlertTriangle, HelpCircle } from 'lucide-react';

const STATUS_CONFIG = {
  consistent: { color: 'var(--terminal-green)', icon: CheckCircle, label: 'CONSISTENT' },
  mismatch: { color: 'var(--cyber-crimson)', icon: XCircle, label: 'MISMATCH' },
  free_provider: { color: 'var(--vibrant-amber)', icon: AlertTriangle, label: 'FREE PROVIDER' },
  lookalike: { color: 'var(--cyber-crimson)', icon: XCircle, label: 'LOOKALIKE' },
  unknown: { color: 'var(--text-muted)', icon: HelpCircle, label: 'UNKNOWN' },
  not_available: { color: 'var(--text-muted)', icon: HelpCircle, label: 'N/A' },
  trusted: { color: 'var(--terminal-green)', icon: CheckCircle, label: 'TRUSTED' },
  untrusted: { color: 'var(--vibrant-amber)', icon: AlertTriangle, label: 'UNTRUSTED' },
  suspicious: { color: 'var(--cyber-crimson)', icon: XCircle, label: 'SUSPICIOUS' },
  legitimate: { color: 'var(--terminal-green)', icon: CheckCircle, label: 'LEGITIMATE' },
  alphanumeric: { color: 'var(--electric-blue)', icon: HelpCircle, label: 'ALPHANUM' },
  shortcode: { color: 'var(--electric-blue)', icon: HelpCircle, label: 'SHORTCODE' },
  url_embedded: { color: 'var(--vibrant-amber)', icon: AlertTriangle, label: 'URL IN SENDER' },
};

function StatusBadge({ status }) {
  if (!status) return null;
  const cfg = STATUS_CONFIG[status] || { color: 'var(--text-muted)', icon: HelpCircle, label: status.toUpperCase() };
  const Icon = cfg.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '10px', fontWeight: '700', letterSpacing: '0.5px',
      color: cfg.color,
      background: `${cfg.color}18`,
      border: `1px solid ${cfg.color}55`,
      padding: '2px 8px', borderRadius: '4px',
    }}>
      <Icon size={10} />
      {cfg.label}
    </span>
  );
}

function IdentityRow({ label, value, icon: Icon, status, extra }) {
  return (
    <div className="identity-status-row" style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
      padding: '10px 0', borderBottom: '1px solid var(--border-subtle)', gap: '12px', flexWrap: 'wrap',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px' }}>
        {Icon && <Icon size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />}
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.3px' }}>
          {label}
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
        {value && (
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', textAlign: 'right' }}>
            {value}
          </span>
        )}
        {status && <StatusBadge status={status} />}
        {extra && (
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'right' }}>{extra}</span>
        )}
      </div>
    </div>
  );
}

function SectionBlock({ title, icon: Icon, children, highlight }) {
  return (
    <div style={{
      background: highlight ? 'rgba(255,51,102,0.04)' : 'rgba(255,255,255,0.02)',
      border: highlight ? '1px solid rgba(255,51,102,0.2)' : '1px solid var(--border-subtle)',
      borderRadius: '6px', padding: '14px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
        {Icon && <Icon size={14} style={{ color: 'var(--electric-blue)' }} />}
        <span style={{ fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--electric-blue)' }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  );
}

export default function IdentityAnalysis({ identityAnalysis, channel }) {
  if (!identityAnalysis) return null;

  const {
    name_check,
    reply_to_check,
    domain_analysis,
    sms_sender_check,
    trust_level,
    trust_explanation,
  } = identityAnalysis;

  const isEmail = channel === 'email';
  const hasMismatch =
    name_check?.status === 'mismatch' ||
    reply_to_check?.status === 'mismatch' ||
    domain_analysis?.trust_status === 'lookalike';

  // Trust level display
  const trustCfg = STATUS_CONFIG[trust_level] || STATUS_CONFIG.unknown;
  const TrustIcon = trustCfg.icon;

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="soc-panel-header">
        <span>Identity &amp; Sender Trust Assessment</span>
        {trust_level && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px',
            fontSize: '11px', fontWeight: '700', color: trustCfg.color,
          }}>
            <TrustIcon size={13} />
            {trust_level.toUpperCase()}
          </span>
        )}
      </div>

      {trust_explanation && (
        <div style={{
          fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5',
          background: 'rgba(0,0,0,0.2)', borderRadius: '5px', padding: '8px 12px',
        }}>
          {trust_explanation}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>

        {/* Name consistency check (email) */}
        {isEmail && name_check && (
          <SectionBlock title="Sender Name Consistency" icon={User} highlight={name_check.status === 'mismatch'}>
            {name_check.sender_name && (
              <IdentityRow label="Displayed Name" value={name_check.sender_name} />
            )}
            {name_check.sender_email && (
              <IdentityRow label="From Address" value={name_check.sender_email} />
            )}
            <IdentityRow label="Name Check" status={name_check.status} extra={name_check.explanation} />
            {name_check.detected_org && (
              <IdentityRow label="Detected Org" value={name_check.detected_org} />
            )}
          </SectionBlock>
        )}

        {/* Reply-To mismatch (email) */}
        {isEmail && reply_to_check && (
          <SectionBlock title="Reply-To Analysis" icon={Mail} highlight={reply_to_check.status === 'mismatch'}>
            {reply_to_check.reply_to && (
              <IdentityRow label="Reply-To" value={reply_to_check.reply_to} />
            )}
            <IdentityRow
              label="Status"
              status={reply_to_check.status}
              extra={reply_to_check.explanation}
            />
            {reply_to_check.reply_to_domain && reply_to_check.sender_domain &&
              reply_to_check.reply_to_domain !== reply_to_check.sender_domain && (
              <IdentityRow
                label="Domain Gap"
                value={`${reply_to_check.sender_domain} → ${reply_to_check.reply_to_domain}`}
                extra="Reply-To domain differs from sender domain"
              />
            )}
          </SectionBlock>
        )}

        {/* Domain analysis (email) */}
        {isEmail && domain_analysis && (
          <SectionBlock title="Domain Trust Analysis" icon={Globe} highlight={domain_analysis.trust_status === 'lookalike'}>
            {domain_analysis.sender_domain && (
              <IdentityRow label="Sender Domain" value={domain_analysis.sender_domain} />
            )}
            {domain_analysis.expected_domain && domain_analysis.expected_domain !== domain_analysis.sender_domain && (
              <IdentityRow label="Expected Domain" value={domain_analysis.expected_domain} />
            )}
            <IdentityRow label="Trust Status" status={domain_analysis.trust_status} />
            {domain_analysis.similarity_score !== undefined && domain_analysis.similarity_score !== null && (
              <IdentityRow
                label="Domain Similarity"
                value={`${(domain_analysis.similarity_score * 100).toFixed(0)}%`}
                extra={domain_analysis.similarity_score > 0.7 ? 'High similarity — possible lookalike' : undefined}
              />
            )}
            {domain_analysis.has_punycode && (
              <IdentityRow
                label="Punycode / IDN"
                value="Detected"
                extra="Domain uses internationalized characters — possible homograph attack"
              />
            )}
            {domain_analysis.domain_indicators && domain_analysis.domain_indicators.length > 0 && (
              <div style={{ marginTop: '6px' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', marginBottom: '6px' }}>
                  Domain Indicators
                </div>
                <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {domain_analysis.domain_indicators.map((ind, i) => (
                    <li key={i} style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', gap: '6px' }}>
                      <span style={{ color: 'var(--vibrant-amber)' }}>▸</span>
                      {ind}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </SectionBlock>
        )}

        {/* SMS sender check */}
        {!isEmail && sms_sender_check && (
          <SectionBlock title="SMS Sender ID Analysis" icon={Smartphone} highlight={sms_sender_check.status === 'suspicious'}>
            {sms_sender_check.sender_id && (
              <IdentityRow label="Sender ID" value={sms_sender_check.sender_id} />
            )}
            <IdentityRow
              label="Sender Type"
              status={sms_sender_check.sender_type || sms_sender_check.status}
              extra={sms_sender_check.explanation}
            />
            {sms_sender_check.indicators && sms_sender_check.indicators.length > 0 && (
              <div style={{ marginTop: '6px' }}>
                <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {sms_sender_check.indicators.map((ind, i) => (
                    <li key={i} style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', gap: '6px' }}>
                      <span style={{ color: 'var(--vibrant-amber)' }}>▸</span>
                      {ind}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </SectionBlock>
        )}
      </div>

      {hasMismatch && (
        <div style={{
          fontSize: '11px', color: 'var(--cyber-crimson)',
          background: 'rgba(255,51,102,0.06)', border: '1px solid rgba(255,51,102,0.25)',
          borderRadius: '5px', padding: '8px 12px', lineHeight: '1.5',
        }}>
          ⚠ Identity inconsistencies detected. Do not respond to this message. Verify sender identity
          independently using a known official contact number or website.
        </div>
      )}
    </div>
  );
}

