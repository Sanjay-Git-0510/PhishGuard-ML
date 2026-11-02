/**
 * TRUSTLENS API Client
 * Extends the existing API client with message analysis and feedback endpoints.
 */

const API_BASE = '/api';

// ─── Existing URL Detection (preserved) ────────────────────────────
export async function checkHealth() {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) throw new Error(`Health check failed: ${response.statusText}`);
  return response.json();
}

export async function predictUrl(url) {
  const response = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Server error (${response.status})`);
  }
  return response.json();
}

export async function getModelInfo() {
  const response = await fetch(`${API_BASE}/model-info`);
  if (!response.ok) throw new Error(`Failed to load model diagnostics: ${response.statusText}`);
  return response.json();
}

export async function getScanHistory(limit = 25) {
  const response = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!response.ok) throw new Error(`Failed to load scan history: ${response.statusText}`);
  return response.json();
}

export async function batchPredict(urls) {
  const response = await fetch(`${API_BASE}/batch-predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || 'Batch prediction failed');
  }
  return response.json();
}

// ─── New: Message Analysis ─────────────────────────────────────────
export async function analyzeEmail(payload) {
  const response = await fetch(`${API_BASE}/analyze-message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Analysis failed (${response.status})`);
  }
  return response.json();
}

export async function analyzeSms(payload) {
  const response = await fetch(`${API_BASE}/analyze-sms`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `SMS analysis failed (${response.status})`);
  }
  return response.json();
}

// ─── New: Feedback ─────────────────────────────────────────────────
export async function submitFeedback(payload) {
  const response = await fetch(`${API_BASE}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || 'Feedback submission failed');
  }
  return response.json();
}

export async function getFeedbackSummary() {
  const response = await fetch(`${API_BASE}/feedback/summary`);
  if (!response.ok) throw new Error(`Failed to load feedback: ${response.statusText}`);
  return response.json();
}
