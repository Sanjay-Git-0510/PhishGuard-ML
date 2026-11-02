import React, { useState } from 'react';
import { ShieldCheck, AlertCircle } from 'lucide-react';
import MessageInput from '../components/MessageInput';
import MessageResult from '../components/MessageResult';
import { analyzeEmail, analyzeSms } from '../services/api';

export default function MessageAnalysis() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [channel, setChannel] = useState('email');
  const [lastPayload, setLastPayload] = useState(null);

  const handleAnalyze = async (selectedChannel, payload) => {
    setLoading(true);
    setError(null);
    setResult(null);
    setChannel(selectedChannel);
    setLastPayload(payload);

    try {
      let data;
      if (selectedChannel === 'email') {
        data = await analyzeEmail(payload);
      } else {
        data = await analyzeSms(payload);
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis failed. Please check your input and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Static analysis assurance banner */}
      <div className="static-assurance-banner">
        <div className="assurance-tag">
          <ShieldCheck size={16} />
          <span>STATIC ANALYSIS ONLY</span>
        </div>
        <span>
          TRUSTLENS analyses message content locally. No links are opened, no data is sent to external
          servers and no actions are performed on your behalf.
        </span>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="static-assurance-banner"
          style={{ background: 'var(--cyber-crimson-dim)', borderColor: 'var(--cyber-crimson)' }}
        >
          <div className="assurance-tag" style={{ color: 'var(--cyber-crimson)' }}>
            <AlertCircle size={16} />
            <span>ANALYSIS ERROR</span>
          </div>
          <span style={{ color: '#fff' }}>{error}</span>
        </div>
      )}

      {/* Input form */}
      <MessageInput onAnalyze={handleAnalyze} loading={loading} />

      {/* Results */}
      {result && (
        <MessageResult
          result={result}
          channel={channel}
          sourcePayload={lastPayload}
          onReanalyze={() => lastPayload && handleAnalyze(channel, lastPayload)}
        />
      )}
    </div>
  );
}
