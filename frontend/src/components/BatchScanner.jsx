import React, { useState } from 'react';
import { Server, ArrowRight } from 'lucide-react';
import { batchPredict } from '../services/api';

export default function BatchScanner({ onInspect }) {
  const [urlsText, setUrlsText] = useState(
`https://www.google.com
http://192.168.1.100/paypal/login.php
https://en.wikipedia.org/wiki/Phishing
http://apple-id-security-lock-unlock-portal-support.xyz/login
https://github.com/torvalds/linux`
  );
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleBatchSubmit = async (e) => {
    e.preventDefault();
    const urlList = urlsText
      .split('\n')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    if (urlList.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const data = await batchPredict(urlList);
      setResults(data);
    } catch (err) {
      setError(err.message || 'Batch prediction failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="soc-panel">
        <div className="soc-panel-header">
          <div className="panel-header-left">
            <Server size={16} style={{ color: 'var(--electric-blue)' }} />
            <span className="panel-title">Batch Static URL Vector Analysis</span>
          </div>
          <span className="panel-badge">Up to 50 URLs / batch</span>
        </div>

        <div className="soc-panel-body">
          <form onSubmit={handleBatchSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Paste target URLs (one per line). All URLs are statically vectorized and classified using the pre-trained scikit-learn model.
            </p>
            <textarea
              className="batch-textarea"
              value={urlsText}
              onChange={(e) => setUrlsText(e.target.value)}
              placeholder="https://example1.com&#10;http://192.168.1.1/login&#10;https://example2.com"
              disabled={loading}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="submit"
                className="analyze-button"
                disabled={loading}
              >
                {loading ? 'Processing Batch...' : 'Analyze Batch Vector'}
                <ArrowRight size={16} />
              </button>
            </div>
          </form>
          {error && (
            <div style={{ marginTop: '14px', color: 'var(--cyber-crimson)', fontSize: '12px' }}>
              ⚠ {error}
            </div>
          )}
        </div>
      </div>

      {results && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            <span className="panel-title">Batch Ingestion Results ({results.total} Analyzed)</span>
            <span className="panel-badge">Airgap Static Scan</span>
          </div>

          <div className="features-table-container">
            <table className="features-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Target URL</th>
                  <th>Probability</th>
                  <th>Risk Tier</th>
                  <th>Observed Indicators</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {results.results.map((res, i) => {
                  const isPhish = res.prediction === 'phishing';
                  return (
                    <tr key={i}>
                      <td>
                        <span className={`risk-tag ${isPhish ? 'high' : 'low'}`} style={{ fontSize: '10px' }}>
                          {res.prediction.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ color: '#fff', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {res.url}
                      </td>
                      <td style={{ color: isPhish ? 'var(--cyber-crimson)' : 'var(--terminal-green)', fontFamily: 'var(--font-mono)' }}>
                        {Math.round(res.probability * 100)}%
                      </td>
                      <td>
                        <span className={`risk-tag ${res.risk_level}`} style={{ fontSize: '10px' }}>
                          {res.risk_level.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                        {res.reasons.length > 0 ? res.reasons.join(', ') : 'No anomalies'}
                      </td>
                      <td>
                        <button
                          className="preset-chip"
                          style={{ fontSize: '10px', padding: '2px 6px' }}
                          onClick={() => onInspect(res.url)}
                        >
                          Deep Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
