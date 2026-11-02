import React, { useState } from 'react';
import { Mail, MessageSquare, Globe, ChevronDown } from 'lucide-react';

const LANGUAGES = ['english', 'hindi', 'kannada', 'code-mixed'];

export default function MessageInput({ onAnalyze, loading }) {
  const [channel, setChannel] = useState('email');
  const [language, setLanguage] = useState('english');
  const [form, setForm] = useState({
    sender_name: '',
    sender_email: '',
    reply_to: '',
    claimed_org: '',
    subject: '',
    message: '',
    sender_id: '',
  });
  const [validationError, setValidationError] = useState('');

  const handleChange = (field) => (e) => {
    setForm((prev) => ({ ...prev, [field]: e.target.value }));
    setValidationError('');
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!form.message.trim()) {
      setValidationError('Message content is required.');
      return;
    }
    const payload = { language };
    if (channel === 'email') {
      payload.sender_name = form.sender_name;
      payload.sender_email = form.sender_email;
      payload.reply_to = form.reply_to;
      payload.claimed_org = form.claimed_org;
      payload.subject = form.subject;
      payload.message = form.message;
    } else {
      payload.sender_id = form.sender_id;
      payload.claimed_org = form.claimed_org;
      payload.message = form.message;
    }
    onAnalyze(channel, payload);
  };

  const inputStyle = {
    width: '100%',
    background: 'var(--bg-surface-3)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '6px',
    padding: '10px 12px',
    color: 'var(--text-primary)',
    fontSize: '13px',
    fontFamily: 'var(--font-sans)',
    outline: 'none',
    transition: 'border-color 0.15s',
    boxSizing: 'border-box',
  };

  const labelStyle = {
    display: 'block',
    fontSize: '11px',
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    color: 'var(--text-muted)',
    marginBottom: '6px',
  };

  const fieldGroup = { display: 'flex', flexDirection: 'column', gap: '4px' };

  return (
    <div className="soc-panel">
      {/* Header */}
      <div className="soc-panel-header scanner-hero-header">
        <div className="panel-header-left">
          <div className="scanner-badge-glow">
            <Mail size={18} style={{ color: 'var(--electric-blue)' }} />
          </div>
          <div>
            <div className="scanner-hero-title">Message Analysis</div>
            <div className="scanner-hero-subtitle">
              Analyze <strong>Email</strong> or <strong>SMS</strong> for phishing, impersonation and social engineering
            </div>
          </div>
        </div>
        <span className="panel-badge-primary">STATIC ANALYSIS</span>
      </div>

      <div className="soc-panel-body">
        {/* Channel Toggle */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
          {[
            { id: 'email', label: 'Email', icon: Mail },
            { id: 'sms', label: 'SMS', icon: MessageSquare },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setChannel(id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 20px',
                borderRadius: '6px',
                border: `1px solid ${channel === id ? 'var(--electric-blue)' : 'var(--border-subtle)'}`,
                background: channel === id ? 'var(--electric-blue-dim)' : 'transparent',
                color: channel === id ? 'var(--electric-blue)' : 'var(--text-secondary)',
                fontWeight: channel === id ? '600' : '400',
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}

          {/* Language Selector */}
          <div style={{ marginLeft: 'auto', position: 'relative' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', ...labelStyle, marginBottom: 0 }}>
              <Globe size={12} />
              <span>Language</span>
            </div>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              style={{
                ...inputStyle,
                width: 'auto',
                paddingRight: '28px',
                cursor: 'pointer',
              }}
            >
              <option value="english">English</option>
              <option value="hindi">Hindi</option>
              <option value="kannada">Kannada</option>
              <option value="code-mixed">Code-Mixed (Indic + English)</option>
            </select>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

            {/* EMAIL FIELDS */}
            {channel === 'email' && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div style={fieldGroup}>
                    <label style={labelStyle}>Sender Name</label>
                    <input
                      style={inputStyle}
                      type="text"
                      placeholder="e.g. Demo Bank Security"
                      value={form.sender_name}
                      onChange={handleChange('sender_name')}
                    />
                  </div>
                  <div style={fieldGroup}>
                    <label style={labelStyle}>Sender Email Address</label>
                    <input
                      style={inputStyle}
                      type="text"
                      placeholder="e.g. security@demobank.example"
                      value={form.sender_email}
                      onChange={handleChange('sender_email')}
                    />
                  </div>
                  <div style={fieldGroup}>
                    <label style={labelStyle}>Reply-To Address</label>
                    <input
                      style={inputStyle}
                      type="text"
                      placeholder="e.g. replies@otherdomain.example"
                      value={form.reply_to}
                      onChange={handleChange('reply_to')}
                    />
                  </div>
                  <div style={fieldGroup}>
                    <label style={labelStyle}>Claimed Organization</label>
                    <input
                      style={inputStyle}
                      type="text"
                      placeholder="e.g. Demo Bank"
                      value={form.claimed_org}
                      onChange={handleChange('claimed_org')}
                    />
                  </div>
                </div>
                <div style={fieldGroup}>
                  <label style={labelStyle}>Email Subject</label>
                  <input
                    style={inputStyle}
                    type="text"
                    placeholder="e.g. Urgent: Your account has been suspended"
                    value={form.subject}
                    onChange={handleChange('subject')}
                  />
                </div>
              </>
            )}

            {/* SMS FIELDS */}
            {channel === 'sms' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={fieldGroup}>
                  <label style={labelStyle}>Sender ID / Phone Number</label>
                  <input
                    style={inputStyle}
                    type="text"
                    placeholder="e.g. DEMOBANK or +91-9876543210"
                    value={form.sender_id}
                    onChange={handleChange('sender_id')}
                  />
                </div>
                <div style={fieldGroup}>
                  <label style={labelStyle}>Claimed Organization</label>
                  <input
                    style={inputStyle}
                    type="text"
                    placeholder="e.g. Demo Bank"
                    value={form.claimed_org}
                    onChange={handleChange('claimed_org')}
                  />
                </div>
              </div>
            )}

            {/* Message Body */}
            <div style={fieldGroup}>
              <label style={labelStyle}>
                {channel === 'email' ? 'Email Message Body' : 'SMS Content'}
              </label>
              <textarea
                style={{
                  ...inputStyle,
                  minHeight: channel === 'email' ? '160px' : '100px',
                  resize: 'vertical',
                  lineHeight: '1.6',
                }}
                placeholder={
                  language === 'hindi'
                    ? 'यहाँ संदेश दर्ज करें...'
                    : language === 'kannada'
                    ? 'ಇಲ್ಲಿ ಸಂದೇಶ ನಮೂದಿಸಿ...'
                    : language === 'code-mixed'
                    ? 'Enter message here (Hindi/Kannada-English mixed text supported)...'
                    : 'Paste the full message content here...'
                }
                value={form.message}
                onChange={handleChange('message')}
                required
              />
            </div>

            {validationError && (
              <div className="scanner-validation-alert">
                <span>{validationError}</span>
              </div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                🔒 Static analysis only — submitted content is never sent to external services.
              </div>
              <button
                type="submit"
                disabled={loading}
                className="analyze-button-prominent"
                style={{ minWidth: '180px', height: '44px', borderRadius: '6px', fontSize: '13px' }}
              >
                {loading ? (
                  <>
                    <span className="loading-spinner" /> Analyzing...
                  </>
                ) : (
                  'Analyze Message ➔'
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}

