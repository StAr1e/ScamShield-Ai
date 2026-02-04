import React, { useState, useEffect } from 'react';
import './Analytics.css';

const API_URL = 'http://localhost:8000';

function AnalyticsDashboard() {
  const [analytics, setAnalytics] = useState(null);
  const [threatIntel, setThreatIntel] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(24);

  useEffect(() => {
    fetchAnalytics();
    fetchThreatIntelligence();
    
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      fetchAnalytics();
      fetchThreatIntelligence();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchAnalytics = async () => {
    try {
      const response = await fetch(`${API_URL}/analytics?hours=${timeRange}`);
      const data = await response.json();
      setAnalytics(data);
      setLoading(false);
    } catch (error) {
      console.error('Analytics fetch error:', error);
      setLoading(false);
    }
  };

  const fetchThreatIntelligence = async () => {
    try {
      const response = await fetch(`${API_URL}/threat-intelligence`);
      const data = await response.json();
      setThreatIntel(data);
    } catch (error) {
      console.error('Threat intelligence fetch error:', error);
    }
  };

  if (loading) {
    return (
      <div className="analytics-loading">
        <div className="spinner-large"></div>
        <p>Loading Analytics...</p>
      </div>
    );
  }

  return (
    <div className="analytics-dashboard">
      <div className="dashboard-header">
        <h1>🛡️ ScamShield AI - Analytics Dashboard</h1>
        <div className="time-range-selector">
          <button 
            className={timeRange === 24 ? 'active' : ''}
            onClick={() => setTimeRange(24)}
          >
            24 Hours
          </button>
          <button 
            className={timeRange === 168 ? 'active' : ''}
            onClick={() => setTimeRange(168)}
          >
            7 Days
          </button>
        </div>
      </div>

      {/* Executive Summary */}
      {threatIntel && (
        <div className="executive-summary">
          <h2>📊 Executive Summary</h2>
          <div className="summary-grid">
            <div className="summary-card">
              <span className="summary-icon">🚨</span>
              <div className="summary-content">
                <div className="summary-value">{threatIntel.executive_summary.total_scams_24h}</div>
                <div className="summary-label">Scams Detected (24h)</div>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-icon">📈</span>
              <div className="summary-content">
                <div className="summary-value">{threatIntel.executive_summary.scam_rate_24h}%</div>
                <div className="summary-label">Scam Rate</div>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-icon">⚡</span>
              <div className="summary-content">
                <div className="summary-value">{threatIntel.executive_summary.average_risk_score.toFixed(1)}</div>
                <div className="summary-label">Avg Risk Score</div>
              </div>
            </div>
            <div className="summary-card trend">
              <span className="summary-icon">📊</span>
              <div className="summary-content">
                <div className="summary-value">{threatIntel.trend}</div>
                <div className="summary-label">Trend</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Detection Summary */}
      {analytics && (
        <div className="detection-summary">
          <h2>🎯 Detection Summary ({timeRange}h)</h2>
          <div className="detection-stats">
            <div className="stat-card scam">
              <div className="stat-number">{analytics.detection_summary.scam_count}</div>
              <div className="stat-label">Scams</div>
            </div>
            <div className="stat-card suspicious">
              <div className="stat-number">{analytics.detection_summary.suspicious_count}</div>
              <div className="stat-label">Suspicious</div>
            </div>
            <div className="stat-card safe">
              <div className="stat-number">{analytics.detection_summary.safe_count}</div>
              <div className="stat-label">Safe</div>
            </div>
            <div className="stat-card total">
              <div className="stat-number">{analytics.total_messages_analyzed}</div>
              <div className="stat-label">Total Analyzed</div>
            </div>
          </div>
        </div>
      )}

      {/* Top Scam Patterns */}
      {analytics && analytics.top_scam_patterns && analytics.top_scam_patterns.length > 0 && (
        <div className="scam-patterns">
          <h2>🔍 Top Scam Patterns</h2>
          <div className="patterns-list">
            {analytics.top_scam_patterns.map((pattern, index) => (
              <div key={index} className="pattern-item">
                <div className="pattern-rank">#{index + 1}</div>
                <div className="pattern-info">
                  <div className="pattern-name">{pattern.description}</div>
                  <div className="pattern-details">{pattern.pattern.replace(/_/g, ' ')}</div>
                </div>
                <div className="pattern-count">{pattern.count}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Emerging Threats */}
      {threatIntel && threatIntel.emerging_threats && threatIntel.emerging_threats.length > 0 && (
        <div className="emerging-threats">
          <h2>🆕 Emerging Threats</h2>
          <div className="threats-list">
            {threatIntel.emerging_threats.map((threat, index) => (
              <div key={index} className="threat-item">
                <span className="threat-icon">⚠️</span>
                <div className="threat-info">
                  <div className="threat-name">{threat.description}</div>
                  <div className="threat-change">
                    {threat.change_percentage > 0 ? '↑' : '↓'} {Math.abs(threat.change_percentage)}% change
                  </div>
                </div>
                <div className="threat-counts">
                  <span className="recent">{threat.recent_count} recent</span>
                  <span className="previous">{threat.previous_count} previous</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Brand Impersonation */}
      {analytics && analytics.brand_impersonation_stats && Object.keys(analytics.brand_impersonation_stats).length > 0 && (
        <div className="brand-impersonation">
          <h2>🏦 Brand Impersonation Stats</h2>
          <div className="brands-grid">
            {Object.entries(analytics.brand_impersonation_stats).map(([brand, count]) => (
              <div key={brand} className="brand-card">
                <div className="brand-name">{brand.replace(/_/g, ' ').toUpperCase()}</div>
                <div className="brand-count">{count} attempts</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Language Distribution */}
      {analytics && analytics.language_distribution && Object.keys(analytics.language_distribution).length > 0 && (
        <div className="language-distribution">
          <h2>🌐 Language Distribution</h2>
          <div className="language-grid">
            {Object.entries(analytics.language_distribution).map(([lang, count]) => (
              <div key={lang} className="language-card">
                <span className="lang-icon">🗣️</span>
                <div className="lang-name">{lang.toUpperCase()}</div>
                <div className="lang-count">{count}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {threatIntel && threatIntel.recommendations && threatIntel.recommendations.length > 0 && (
        <div className="recommendations-section">
          <h2>💡 Threat Intelligence Recommendations</h2>
          <div className="recommendations-list">
            {threatIntel.recommendations.map((rec, index) => (
              <div key={index} className="recommendation-item">
                {rec}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="dashboard-footer">
        <p>Last updated: {analytics ? new Date(analytics.generated_at).toLocaleString() : 'N/A'}</p>
        <p>Auto-refresh every 30 seconds</p>
      </div>
    </div>
  );
}

export default AnalyticsDashboard;
