/**
 * API Client for AegisThreat Phishing Detection Backend
 */

const API_BASE = '/api';

export async function checkHealth() {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.statusText}`);
  }
  return response.json();
}

export async function predictUrl(url) {
  const response = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const message = errorData.detail || `Server error (${response.status})`;
    throw new Error(message);
  }

  return response.json();
}

export async function getModelInfo() {
  const response = await fetch(`${API_BASE}/model-info`);
  if (!response.ok) {
    throw new Error(`Failed to load model diagnostics: ${response.statusText}`);
  }
  return response.json();
}

export async function getScanHistory(limit = 25) {
  const response = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed to load scan history: ${response.statusText}`);
  }
  return response.json();
}

export async function batchPredict(urls) {
  const response = await fetch(`${API_BASE}/batch-predict`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ urls }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || 'Batch prediction failed');
  }

  return response.json();
}
