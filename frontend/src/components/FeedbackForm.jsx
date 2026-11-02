import React, { useState } from 'react';
import { ThumbsUp, ThumbsDown, CheckCircle, AlertCircle, Send } from 'lucide-react';
import { submitFeedback } from '../services/api';

export default function FeedbackForm({
  analysisId,
  originalRiskLevel,
  channel,
  language,
  messageText,
  onReanalyze,
}) {
  const [selected, setSelected] = useState(null); // 'legitimate' | 'still_suspicious'
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [retrained, setRetrained] = useState(false);
  const [serverMessage, setServerMessage] = useState('');
  const [error, setError] = useState(null);

  if (!analysisId) return null;

  const handleSubmit = async () => {
    if (!selected) return;
    setLoading(true);
    setError(null);
    try {
      const result = await submitFeedback({
        analysis_id: analysisId,
        channel: channel || 'unknown',
        language: language || 'english',
        original_risk_level: originalRiskLevel || 'unknown',
        user_feedback: selected,
        feedback_reason: reason.trim() || null,
        message_text: messageText || null,
      });
      setRetrained(Boolean(result.retrained));
      setServerMessage(result.message || '');
      setSubmitted(true);
    } catch (err) {
      setError(err.message || 'Feedback submission failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (submitted) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', gap: '10px',
        background: 'rgba(0,255,102,0.06)', border: '1px solid rgba(0,255,102,0.25)',
        borderRadius: '8px', padding: '14px 18px',
      }}>
        <CheckCircle size={18} style={{ color: 'var(--terminal-green)', flexShrink: 0 }} />
        <div>
          <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--terminal-green)' }}>
            {retrained ? 'Challenge accepted — model retrained' : 'Feedback recorded'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {serverMessage || 'Thank you. Your report helps improve detection accuracy.'}
            {retrained ? ' Analyze the same message again to see the updated risk result.' : ''}
          </div>
          {onReanalyze && (
            <button
              onClick={onReanalyze}
              className="analyze-button"
              style={{ marginTop: '10px', padding: '8px 14px', fontSize: '12px', cursor: 'pointer' }}
            >
              Analyze again with updated model
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="soc-panel-header">
        <span>Challenge this result</span>
        <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          ID: {analysisId}
        </span>
      </div>

      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0, lineHeight: '1.5' }}>
        If this is a false positive — a legitimate or benign message that was flagged —
        report it here. Your correction is used to retrain the classifier so the next
        analysis of the same message reflects the updated label.
      </p>

      {/* Choice buttons */}
      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button
          onClick={() => setSelected('legitimate')}
          style={{
            flex: 1, minWidth: '160px',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
            padding: '12px 16px', borderRadius: '6px', cursor: 'pointer',
            border: `1px solid ${selected === 'legitimate' ? 'var(--terminal-green)' : 'var(--border-subtle)'}`,
            background: selected === 'legitimate' ? 'rgba(0,255,102,0.08)' : 'rgba(255,255,255,0.03)',
            color: selected === 'legitimate' ? 'var(--terminal-green)' : 'var(--text-secondary)',
            fontSize: '13px', fontWeight: '600', transition: 'all 0.15s',
          }}
        >
          <ThumbsUp size={15} />
          This message is legitimate
        </button>
        <button
          onClick={() => setSelected('still_suspicious')}
          style={{
            flex: 1, minWidth: '160px',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
            padding: '12px 16px', borderRadius: '6px', cursor: 'pointer',
            border: `1px solid ${selected === 'still_suspicious' ? 'var(--cyber-crimson)' : 'var(--border-subtle)'}`,
            background: selected === 'still_suspicious' ? 'rgba(255,51,102,0.08)' : 'rgba(255,255,255,0.03)',
            color: selected === 'still_suspicious' ? 'var(--cyber-crimson)' : 'var(--text-secondary)',
            fontSize: '13px', fontWeight: '600', transition: 'all 0.15s',
          }}
        >
          <ThumbsDown size={15} />
          Still suspicious
        </button>
      </div>

      {selected && (
        <textarea
          value={reason}
          onChange={e => setReason(e.target.value)}
          placeholder="Optional: briefly explain why (max 300 characters)"
          maxLength={300}
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)',
            borderRadius: '6px', padding: '10px 12px',
            color: 'var(--text-primary)', fontSize: '12px', fontFamily: 'inherit',
            resize: 'vertical', outline: 'none',
          }}
        />
      )}

      {error && (
        <div style={{
          display: 'flex', gap: '8px', alignItems: 'center',
          background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.25)',
          borderRadius: '5px', padding: '8px 12px', fontSize: '12px', color: 'var(--cyber-crimson)',
        }}>
          <AlertCircle size={13} />
          {error}
        </div>
      )}

      <button
        onClick={handleSubmit}
        disabled={!selected || loading}
        className="analyze-button"
        style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '10px 20px', width: 'fit-content',
          opacity: !selected || loading ? 0.5 : 1,
          cursor: !selected || loading ? 'not-allowed' : 'pointer',
        }}
      >
        <Send size={14} />
        {loading ? 'Retraining…' : 'Submit challenge'}
      </button>
    </div>
  );
}
