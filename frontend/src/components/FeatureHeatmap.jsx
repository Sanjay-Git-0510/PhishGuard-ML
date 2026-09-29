import React from 'react';
import { Layers } from 'lucide-react';

export default function FeatureHeatmap({ features }) {
  // If no scan has been run yet, use baseline neutral definitions
  const f = features || {};

  const matrixItems = [
    {
      id: 'protocol',
      name: 'Protocol Transport',
      value: f.is_https === 1 ? 'TLS HTTPS Encrypted' : (f.is_https === 0 ? 'Plaintext HTTP (No TLS)' : 'Awaiting Target'),
      severity: f.is_https === 1 ? 'clean' : (f.is_https === 0 ? 'critical' : 'clean'),
      desc: 'Transport layer encryption flag. Phishing kits frequently host on unencrypted HTTP.',
    },
    {
      id: 'host_authority',
      name: 'Host Authority (IP vs Domain)',
      value: f.is_ip_address === 1 ? 'IPv4/IPv6 Literal' : 'Valid FQDN',
      severity: f.is_ip_address === 1 ? 'critical' : 'clean',
      desc: 'IP literals bypass standard DNS registration and certificate verification pipelines.',
    },
    {
      id: 'subdomain_depth',
      name: 'Subdomain Nesting',
      value: f.num_subdomains !== undefined ? `${f.num_subdomains} Levels` : '0 Levels',
      severity: (f.num_subdomains || 0) >= 3 ? 'critical' : ((f.num_subdomains || 0) >= 2 ? 'warning' : 'clean'),
      desc: 'Attackers create excessive subdomains to impersonate legitimate brand hierarchies.',
    },
    {
      id: 'tld_reputation',
      name: 'TLD Reputation Index',
      value: f.suspicious_tld === 1 ? 'High-Abuse Extension' : 'Standard Registry',
      severity: f.suspicious_tld === 1 ? 'critical' : 'clean',
      desc: 'Disreputable registries (.xyz, .top, .buzz) have high historical correlation with disposable attack domains.',
    },
    {
      id: 'keyword_traps',
      name: 'Credential Lure Keywords',
      value: f.has_suspicious_keywords === 1 ? 'Detected (Login/Verify/Auth)' : 'None Identified',
      severity: f.has_suspicious_keywords === 1 ? 'warning' : 'clean',
      desc: 'Words like "login", "banking", "verify", and "account" targeting credential interception.',
    },
    {
      id: 'symbol_trickery',
      name: 'Authority Deception (@ Symbol)',
      value: f.num_at_symbols > 0 ? `Triggered (${f.num_at_symbols} @ found)` : 'Clean',
      severity: (f.num_at_symbols || 0) > 0 ? 'critical' : 'clean',
      desc: 'RFC standards allow userinfo before @ symbol; browsers discard the prefix and route to the destination.',
    },
    {
      id: 'entropy_score',
      name: 'Shannon Entropy',
      value: f.url_entropy ? `${f.url_entropy.toFixed(3)} bits/char` : '3.420 bits/char',
      severity: (f.url_entropy || 0) > 4.5 ? 'critical' : ((f.url_entropy || 0) > 4.0 ? 'warning' : 'clean'),
      desc: 'Measures lexical randomness. High entropy flags algorithmically generated domains (DGA) or hex payloads.',
    },
    {
      id: 'shortener_mask',
      name: 'Shortener Masking',
      value: f.is_shortened === 1 ? 'Masked Host (Shortener)' : 'Direct Endpoint',
      severity: f.is_shortened === 1 ? 'warning' : 'clean',
      desc: 'Masking services (bit.ly, tinyurl) prevent human inspection of the destination URL before clicking.',
    },
  ];

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <div className="panel-header-left">
          <Layers size={16} style={{ color: 'var(--vibrant-amber)' }} />
          <span className="panel-title">Dynamic Vulnerability Heatmap Matrix</span>
        </div>
        <span className="panel-badge">
          {features ? 'Evaluated against active vector' : 'Baseline Reference'}
        </span>
      </div>

      <div className="soc-panel-body">
        <div className="heatmap-grid">
          {matrixItems.map((item) => (
            <div key={item.id} className="heatmap-cell">
              <div className="heatmap-cell-top">
                <span className="heatmap-cell-title">{item.name}</span>
                <span className={`heatmap-severity-tag severity-${item.severity}`}>
                  {item.severity.toUpperCase()}
                </span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: '#fff' }}>
                {item.value}
              </div>
              <div className="heatmap-cell-desc">
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
