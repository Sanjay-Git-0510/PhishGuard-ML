import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Eye, 
  Hash
} from 'lucide-react';

export default function ResultCard({ result }) {
  if (!result) return null;

  const isPhishing = result.prediction === 'phishing';
  const probPercent = Math.round(result.probability * 100);

  const getRiskClass = (level) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'high';
      case 'medium': return 'medium';
      default: return 'low';
    }
  };

  return (
    <div className={`result-banner-card ${isPhishing ? 'phishing' : 'legitimate'}`}>
      <div className="result-header-row">
        <div className="result-status-block">
          <div className="status-badge-icon">
            {isPhishing ? <ShieldAlert size={28} /> : <ShieldCheck size={28} />}
          </div>
          <div className="status-classification-text">
            <h2>{isPhishing ? 'PHISHING THREAT DETECTED' : 'LEGITIMATE URL CONFIRMED'}</h2>
            <p>
              {isPhishing 
                ? 'High-confidence indicators associated with credential theft, deception, or malware.'
                : 'Structural parameters align with standard legitimate domain architectures.'}
            </p>
          </div>
        </div>

        <div className={`risk-tag ${getRiskClass(result.risk_level)}`}>
          RISK LEVEL: {result.risk_level?.toUpperCase()}
        </div>
      </div>

      {/* Primary Metrics Grid */}
      <div className="result-metrics-grid">
        <div className="metric-item">
          <span className="metric-label">Target Destination</span>
          <div style={{ 
            fontFamily: 'var(--font-mono)', 
            fontSize: '13px', 
            color: '#fff', 
            wordBreak: 'break-all' 
          }}>
            {result.url}
          </div>
        </div>

        <div className="metric-item">
          <span className="metric-label">Model Probability</span>
          <span className="metric-value-huge" style={{ 
            color: isPhishing ? 'var(--cyber-crimson)' : 'var(--terminal-green)' 
          }}>
            {probPercent}%
          </span>
        </div>

        <div className="metric-item">
          <span className="metric-label">Inspection Method</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--electric-blue)' }}>
            Static Lexical Analysis
          </span>
        </div>

        <div className="metric-item">
          <span className="metric-label">Timestamp (UTC)</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
            {new Date(result.timestamp).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Observed Indicators / Explanations */}
      <div className="indicators-container">
        <div className="indicators-heading">
          <Eye size={14} />
          <span>Observed URL Characteristics & Threat Indicators</span>
        </div>

        {result.reasons && result.reasons.length > 0 ? (
          <ul className="indicators-list">
            {result.reasons.map((reason, idx) => (
              <li key={idx} className="indicator-row">
                <span className="indicator-bullet"></span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic' }}>
            No malicious structural anomalies observed. All inspected lexical parameters within safe thresholds.
          </div>
        )}
      </div>

      {/* Extracted Features Table */}
      {result.features && (
        <div className="soc-panel" style={{ marginTop: '4px', background: 'var(--bg-surface-2)' }}>
          <div className="soc-panel-header" style={{ padding: '10px 16px' }}>
            <div className="panel-header-left">
              <Hash size={14} style={{ color: 'var(--electric-blue)' }} />
              <span className="panel-title" style={{ fontSize: '12px' }}>
                Extracted Feature Breakdown (20 Vectors)
              </span>
            </div>
            <span className="panel-badge">scikit-learn input</span>
          </div>

          <div className="features-table-container">
            <table className="features-table">
              <thead>
                <tr>
                  <th>Feature Parameter</th>
                  <th>Extracted Value</th>
                  <th>Type</th>
                  <th>Security Context</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(result.features).map(([key, val]) => (
                  <tr key={key}>
                    <td style={{ color: 'var(--text-primary)' }}>{key}</td>
                    <td>
                      <span className="feature-value-badge">
                        {typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(4)) : String(val)}
                      </span>
                    </td>
                    <td>{typeof val === 'number' && (val === 0 || val === 1) ? 'Boolean Flag' : 'Numeric / Count'}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                      {getFeatureDescription(key)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function getFeatureDescription(featureName) {
  const map = {
    url_length: 'Total length in characters (long URLs often hide deception)',
    hostname_length: 'Length of the hostname/FQDN component',
    path_length: 'Length of the URL resource path',
    query_length: 'Length of query parameters string',
    num_dots: 'Count of period characters across the entire URL',
    num_hyphens: 'Count of hyphens (often used to mimic brand names)',
    num_underscores: 'Count of underscore symbols',
    num_slashes: 'Count of forward slash delimiters',
    num_question_marks: 'Count of query parameter initiators',
    num_equal_signs: 'Count of parameter assignment operators',
    num_at_symbols: 'Count of @ symbols (used to disguise target host)',
    num_digits: 'Count of numeric digits present in the string',
    digit_ratio: 'Proportion of digits relative to total string length',
    num_subdomains: 'Depth of subdomain nesting beyond root domain',
    is_ip_address: '1 if host is raw IPv4/IPv6 literal without domain',
    is_https: '1 if secure HTTPS protocol, 0 if unencrypted HTTP',
    has_suspicious_keywords: '1 if words like login/verify/secure/update are found',
    is_shortened: '1 if hostname matches known URL shortener service',
    suspicious_tld: '1 if TLD is in high-abuse registry list',
    url_entropy: 'Shannon entropy measuring randomness/obfuscation',
  };
  return map[featureName] || 'Static structural signal';
}
