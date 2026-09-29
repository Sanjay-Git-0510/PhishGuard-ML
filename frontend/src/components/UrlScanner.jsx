import React, { useState } from 'react';
import { Search, ArrowRight, X, AlertCircle, Sparkles } from 'lucide-react';

export default function UrlScanner({ onAnalyze, loading, inputUrl, setInputUrl }) {
  const [localError, setLocalError] = useState(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputUrl || !inputUrl.trim()) {
      setLocalError('Please type or paste a website URL into the box below before clicking Predict.');
      return;
    }
    setLocalError(null);
    onAnalyze(inputUrl.trim());
  };

  const loadPreset = (presetUrl) => {
    setInputUrl(presetUrl);
    setLocalError(null);
    onAnalyze(presetUrl);
  };

  const clearInput = () => {
    setInputUrl('');
    setLocalError(null);
  };

  const samplePresets = [
    {
      label: 'Google Search',
      url: 'https://www.google.com/search?q=cybersecurity+threat+intelligence',
      type: 'benign'
    },
    {
      label: 'Wikipedia TLS',
      url: 'https://en.wikipedia.org/wiki/Transport_Layer_Security',
      type: 'benign'
    },
    {
      label: 'GitHub Security',
      url: 'https://github.com/torvalds/linux',
      type: 'benign'
    },
    {
      label: 'IP Host Scam',
      url: 'http://192.168.1.100/paypal/login.php?verify=1',
      type: 'phish'
    },
    {
      label: 'Brand Spoof Subdomains',
      url: 'http://login.microsoft.com.account-verification.suspicious-domain.com/signin',
      type: 'phish'
    },
    {
      label: '@ Redirect Trick',
      url: 'http://www.paypal.com@verify-identity-billing-portal.com/login.html',
      type: 'phish'
    },
    {
      label: 'Typosquat: paypa1.com',
      url: 'https://paypa1.com',
      type: 'phish'
    },
    {
      label: 'High-Abuse TLD',
      url: 'http://apple-id-security-lock-unlock-portal-support.xyz/login',
      type: 'phish'
    }
  ];

  return (
    <div className="soc-panel scanner-hero-panel">
      <div className="soc-panel-header scanner-hero-header">
        <div className="panel-header-left">
          <div className="scanner-badge-glow">
            <Search size={18} style={{ color: 'var(--electric-blue)' }} />
          </div>
          <div>
            <h2 className="scanner-hero-title">ENTER ANY URL TO PREDICT</h2>
            <p className="scanner-hero-subtitle">
              Type or paste any website address or link below to test whether it is <strong>Legitimate</strong> or a <strong>Phishing Threat</strong>:
            </p>
          </div>
        </div>
        <span className="panel-badge-primary">PRIMARY SCANNER</span>
      </div>

      <div className="soc-panel-body" style={{ padding: '24px' }}>
        <form onSubmit={handleSubmit} className="scanner-input-container">
          <div className="scanner-input-box-wrapper">
            <div className="input-prefix-icon-container">
              <Search size={20} style={{ color: 'var(--electric-blue)' }} />
            </div>

            <input
              id="url-input-field"
              type="text"
              className="soc-url-input-prominent"
              placeholder="Paste or type any URL here (e.g. https://your-link.com or paypal-security-login.com)..."
              value={inputUrl}
              onChange={(e) => {
                setInputUrl(e.target.value);
                if (localError) setLocalError(null);
              }}
              autoFocus
              disabled={loading}
              aria-label="Target URL to inspect"
            />

            {inputUrl && (
              <button
                type="button"
                className="input-clear-icon-btn"
                onClick={clearInput}
                title="Clear input"
                disabled={loading}
              >
                <X size={16} />
              </button>
            )}

            <button
              id="analyze-url-btn"
              type="submit"
              className="analyze-button-prominent"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="loading-spinner"></span>
                  <span>PREDICTING...</span>
                </>
              ) : (
                <>
                  <Sparkles size={16} />
                  <span>PREDICT URL</span>
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>

          {localError && (
            <div className="scanner-validation-alert">
              <AlertCircle size={16} />
              <span>{localError}</span>
            </div>
          )}

          {/* Helper hint */}
          <div className="scanner-input-hint">
            <span>💡 <strong>How it works:</strong> Type any domain, link, or IP address (with or without <code>https://</code>) and click <strong>PREDICT URL</strong>. AegisThreat statically parses lexical patterns, character entropy, and structural cues without visiting the destination.</span>
          </div>

          {/* Quick Test Presets */}
          <div className="presets-container-box">
            <div className="presets-header-row">
              <span className="presets-label">OR QUICK-TEST WITH SAMPLE SIGNATURES:</span>
              <span className="presets-sublabel">Click any chip below to load it into the input box:</span>
            </div>
            <div className="presets-row">
              {samplePresets.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  className={`preset-chip ${p.type === 'benign' ? 'benign-chip' : 'phish-chip'}`}
                  onClick={() => loadPreset(p.url)}
                  disabled={loading}
                >
                  {p.type === 'benign' ? '✓ Safe: ' : '⚠ Threat: '}
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
