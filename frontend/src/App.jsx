import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import HeaderTelemetry from './components/HeaderTelemetry';
import UrlScanner from './components/UrlScanner';
import ResultCard from './components/ResultCard';
import FeatureHeatmap from './components/FeatureHeatmap';
import AssetPriorityCards from './components/AssetPriorityCards';
import LogIngestionFeed from './components/LogIngestionFeed';
import ModelTelemetry from './components/ModelTelemetry';
import BatchScanner from './components/BatchScanner';
import { checkHealth, predictUrl, getModelInfo, getScanHistory } from './services/api';
import { ShieldCheck, AlertCircle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentResult, setCurrentResult] = useState(null);
  const [error, setError] = useState(null);

  const [health, setHealth] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [logs, setLogs] = useState([]);

  const fetchInitialData = useCallback(async () => {
    try {
      const [h, m, l] = await Promise.all([
        checkHealth().catch(() => null),
        getModelInfo().catch(() => null),
        getScanHistory().catch(() => []),
      ]);
      if (h) setHealth(h);
      if (m) setModelInfo(m);
      if (l) setLogs(l);
    } catch (err) {
      console.warn('Initial data load warning:', err);
    }
  }, []);

  // Load telemetry data on mount
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [h, m, l] = await Promise.all([
          checkHealth().catch(() => null),
          getModelInfo().catch(() => null),
          getScanHistory().catch(() => []),
        ]);
        if (active) {
          if (h) setHealth(h);
          if (m) setModelInfo(m);
          if (l) setLogs(l);
        }
      } catch (err) {
        console.warn('Initial data load warning:', err);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleAnalyze = async (url) => {
    setLoading(true);
    setError(null);
    try {
      const data = await predictUrl(url);
      setCurrentResult(data);
      // Refresh logs
      const updatedLogs = await getScanHistory().catch(() => logs);
      setLogs(updatedLogs);
    } catch (err) {
      setError(err.message || 'Analysis failed. Verify URL structure.');
      setCurrentResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleInspectFromHistory = (url) => {
    setActiveTab('scanner');
    setInputUrl(url);
    handleAnalyze(url);
  };

  return (
    <div className="soc-app-container">
      {/* Left-Hand SOC Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        health={health}
      />

      {/* Main Workspace */}
      <main className="soc-main-area">
        <HeaderTelemetry
          modelInfo={modelInfo}
          health={health}
        />

        <div className="soc-content-scroll">
          {/* Static Analysis Security Notice */}
          <div className="static-assurance-banner">
            <div className="assurance-tag">
              <ShieldCheck size={16} />
              <span>AIRGAP SAFE-MODE ENFORCED</span>
            </div>
            <span>Static URL analysis only — the submitted website is not visited by this application.</span>
          </div>

          {error && (
            <div className="static-assurance-banner" style={{ background: 'var(--cyber-crimson-dim)', borderColor: 'var(--cyber-crimson)' }}>
              <div className="assurance-tag" style={{ color: 'var(--cyber-crimson)' }}>
                <AlertCircle size={16} />
                <span>INSPECTION ERROR</span>
              </div>
              <span style={{ color: '#fff' }}>{error}</span>
            </div>
          )}

          {activeTab !== 'scanner' && (
            <div className="tab-quick-action-bar">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="status-indicator-dot"></span>
                <span>Want to test or predict a specific website URL?</span>
              </div>
              <button
                className="analyze-button"
                style={{ padding: '8px 16px', fontSize: '12px' }}
                onClick={() => setActiveTab('scanner')}
              >
                <span>Open URL Input Scanner ➔</span>
              </button>
            </div>
          )}

          {/* Tab 1: Primary Threat URL Scanner */}
          {activeTab === 'scanner' && (
            <>
              <UrlScanner
                onAnalyze={handleAnalyze}
                loading={loading}
                inputUrl={inputUrl}
                setInputUrl={setInputUrl}
              />

              {currentResult && (
                <ResultCard result={currentResult} />
              )}

              {/* Dynamic Vulnerability Heatmap Matrix */}
              <FeatureHeatmap features={currentResult?.features} />

              {/* Asset Priority Triage Cards */}
              <AssetPriorityCards result={currentResult} />

              {/* Live Ingestion Feed */}
              <LogIngestionFeed
                logs={logs}
                onRefresh={fetchInitialData}
                onInspect={handleInspectFromHistory}
              />
            </>
          )}

          {/* Tab 2: Dedicated Vulnerability Matrix */}
          {activeTab === 'heatmap' && (
            <>
              <FeatureHeatmap features={currentResult?.features} />
              <AssetPriorityCards result={currentResult} />
            </>
          )}

          {/* Tab 3: Dedicated Logs */}
          {activeTab === 'logs' && (
            <LogIngestionFeed
              logs={logs}
              onRefresh={fetchInitialData}
              onInspect={handleInspectFromHistory}
            />
          )}

          {/* Tab 4: Model Telemetry */}
          {activeTab === 'model' && (
            <ModelTelemetry modelInfo={modelInfo} />
          )}

          {/* Tab 5: Batch Scanner */}
          {activeTab === 'batch' && (
            <BatchScanner onInspect={handleInspectFromHistory} />
          )}
        </div>
      </main>
    </div>
  );
}
