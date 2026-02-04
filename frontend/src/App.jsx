import React, { useState } from 'react';
import './App.css';

const API_URL = 'http://localhost:8000';

function App() {
  const [message, setMessage] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeMessage = async () => {
    if (!message.trim()) {
      setError('Please enter a message to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message }),
      });

      if (!response.ok) {
        throw new Error('Analysis failed');
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError('Failed to analyze message. Make sure the backend server is running.');
      console.error('Analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  const clearAnalysis = () => {
    setMessage('');
    setAnalysis(null);
    setError(null);
  };

  const getClassificationColor = (classification) => {
    switch (classification) {
      case 'SCAM':
        return 'var(--color-danger)';
      case 'SUSPICIOUS':
        return 'var(--color-warning)';
      case 'SAFE':
        return 'var(--color-safe)';
      default:
        return 'var(--color-text)';
    }
  };

  const getClassificationIcon = (classification) => {
    switch (classification) {
      case 'SCAM':
        return '🚨';
      case 'SUSPICIOUS':
        return '⚠️';
      case 'SAFE':
        return '✅';
      default:
        return '🔍';
    }
  };

  const highlightKeywords = (text, keywords) => {
    if (!keywords || keywords.length === 0) return text;
    
    let highlightedText = text;
    keywords.forEach(keyword => {
      const regex = new RegExp(`(${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      highlightedText = highlightedText.replace(regex, '<mark>$1</mark>');
    });
    
    return highlightedText;
  };

  return (
    <div className="app">
      {/* Animated Background */}
      <div className="background-animation">
        <div className="grid-overlay"></div>
        <div className="scanning-line"></div>
      </div>

      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo-section">
            <div className="shield-icon">🛡️</div>
            <div className="logo-text">
              <h1>ScamShield AI</h1>
              <p className="tagline">AI-Powered Fraud Detection</p>
            </div>
          </div>
          <div className="status-indicator">
            <span className="status-dot"></span>
            <span className="status-text">System Active</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-content">
        <div className="container">
          {/* Input Section */}
          <section className="input-section">
            <div className="section-header">
              <h2>Analyze Suspicious Message</h2>
              <p>Paste any message you've received to check for scam indicators</p>
            </div>

            <div className="input-wrapper">
              <textarea
                className="message-input"
                placeholder="Paste your suspicious message here...&#10;&#10;Example: 'URGENT! Your account will be suspended in 24 hours. Click here to verify: bit.ly/xyz123'"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                rows={8}
                disabled={loading}
              />
              <div className="character-count">
                {message.length} / 5000 characters
              </div>
            </div>

            <div className="action-buttons">
              <button
                className="btn btn-primary"
                onClick={analyzeMessage}
                disabled={loading || !message.trim()}
              >
                {loading ? (
                  <>
                    <span className="spinner"></span>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <span className="btn-icon">🔍</span>
                    Analyze Message
                  </>
                )}
              </button>
              
              {(message || analysis) && (
                <button
                  className="btn btn-secondary"
                  onClick={clearAnalysis}
                  disabled={loading}
                >
                  Clear
                </button>
              )}
            </div>

            {error && (
              <div className="error-message">
                <span className="error-icon">⚠️</span>
                {error}
              </div>
            )}
          </section>

          {/* Results Section */}
          {analysis && (
            <section className="results-section" style={{ animationDelay: '0.1s' }}>
              {/* Classification Banner */}
              <div 
                className={`classification-banner classification-${analysis.classification.toLowerCase()}`}
                style={{ '--classification-color': getClassificationColor(analysis.classification) }}
              >
                <div className="classification-header">
                  <span className="classification-icon">
                    {getClassificationIcon(analysis.classification)}
                  </span>
                  <div className="classification-text">
                    <h3>{analysis.classification}</h3>
                    <p>Risk Level: {analysis.classification === 'SCAM' ? 'Critical' : analysis.classification === 'SUSPICIOUS' ? 'High' : 'Low'}</p>
                  </div>
                </div>
                
                <div className="risk-score-display">
                  <div className="score-circle">
                    <svg className="progress-ring" width="120" height="120">
                      <circle
                        className="progress-ring-circle-bg"
                        stroke="rgba(255,255,255,0.1)"
                        strokeWidth="8"
                        fill="transparent"
                        r="52"
                        cx="60"
                        cy="60"
                      />
                      <circle
                        className="progress-ring-circle"
                        stroke={getClassificationColor(analysis.classification)}
                        strokeWidth="8"
                        fill="transparent"
                        r="52"
                        cx="60"
                        cy="60"
                        style={{
                          strokeDasharray: `${2 * Math.PI * 52}`,
                          strokeDashoffset: `${2 * Math.PI * 52 * (1 - analysis.risk_score / 100)}`,
                        }}
                      />
                    </svg>
                    <div className="score-text">
                      <span className="score-number">{Math.round(analysis.risk_score)}</span>
                      <span className="score-label">Risk Score</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* ML Metrics */}
              {(analysis.ml_probability !== undefined || analysis.rule_score !== undefined) && (
                <div className="metrics-banner">
                  <div className="metric-item">
                    <span className="metric-icon">🤖</span>
                    <div className="metric-content">
                      <span className="metric-label">ML Probability</span>
                      <span className="metric-value">{(analysis.ml_probability * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                  <div className="metric-item">
                    <span className="metric-icon">📋</span>
                    <div className="metric-content">
                      <span className="metric-label">Rule Score</span>
                      <span className="metric-value">{(analysis.rule_score * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                  {analysis.language_detected && (
                    <div className="metric-item">
                      <span className="metric-icon">🌐</span>
                      <div className="metric-content">
                        <span className="metric-label">Language</span>
                        <span className="metric-value">{analysis.language_detected.toUpperCase()}</span>
                      </div>
                    </div>
                  )}
                  {analysis.triggered_rules && analysis.triggered_rules.length > 0 && (
                    <div className="metric-item">
                      <span className="metric-icon">⚠️</span>
                      <div className="metric-content">
                        <span className="metric-label">Rules Triggered</span>
                        <span className="metric-value">{analysis.triggered_rules.length}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Analysis Details */}
              <div className="analysis-grid">
                {/* Highlighted Message */}
                <div className="analysis-card">
                  <h4 className="card-title">
                    <span className="card-icon">📝</span>
                    Analyzed Message
                  </h4>
                  <div 
                    className="highlighted-message"
                    dangerouslySetInnerHTML={{
                      __html: highlightKeywords(message, analysis.highlighted_keywords)
                    }}
                  />
                  {analysis.highlighted_keywords.length > 0 && (
                    <div className="keyword-legend">
                      <span className="legend-marker"></span>
                      <span className="legend-text">Highlighted: Suspicious keywords detected</span>
                    </div>
                  )}
                </div>

                {/* Explanation */}
                <div className="analysis-card">
                  <h4 className="card-title">
                    <span className="card-icon">🔎</span>
                    Detection Explanation
                  </h4>
                  <ul className="explanation-list">
                    {analysis.explanation.map((exp, index) => (
                      <li key={index} className="explanation-item">
                        {exp}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Safety Recommendations */}
                <div className="analysis-card recommendations-card">
                  <h4 className="card-title">
                    <span className="card-icon">💡</span>
                    Safety Recommendations
                  </h4>
                  <ul className="recommendations-list">
                    {analysis.safety_recommendations.map((rec, index) => (
                      <li key={index} className="recommendation-item">
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Timestamp */}
              <div className="analysis-footer">
                <span className="timestamp">
                  Analyzed at: {new Date(analysis.analyzed_at).toLocaleString()}
                </span>
              </div>
            </section>
          )}

          {/* Example Section */}
          {!analysis && !loading && (
            <section className="examples-section">
              <h3>Try These Examples</h3>
              <div className="example-cards">
                <button
                  className="example-card"
                  onClick={() => setMessage("URGENT! Your bank account will be suspended in 24 hours. Click here to verify your identity immediately: bit.ly/verify-now")}
                >
                  <span className="example-label scam-label">SCAM</span>
                  <p>"URGENT! Your bank account will be suspended..."</p>
                </button>
                
                <button
                  className="example-card"
                  onClick={() => setMessage("Dear customer, we noticed unusual activity on your account. Please confirm your recent transaction by clicking the link below.")}
                >
                  <span className="example-label suspicious-label">SUSPICIOUS</span>
                  <p>"We noticed unusual activity on your account..."</p>
                </button>
                
                <button
                  className="example-card"
                  onClick={() => setMessage("Your order #12345 has been shipped and will arrive on Monday. Track your package at amazon.com/orders")}
                >
                  <span className="example-label safe-label">SAFE</span>
                  <p>"Your order has been shipped and will arrive..."</p>
                </button>
              </div>
            </section>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <p>ScamShield AI - Protecting users from digital fraud</p>
          <p className="footer-note">Always verify suspicious messages through official channels</p>
        </div>
      </footer>
    </div>
  );
}

export default App;
