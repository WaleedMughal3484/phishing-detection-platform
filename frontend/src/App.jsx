import { useState } from "react";

import {
  SAFE_URL_SAMPLE,
  SUSPICIOUS_EMAIL_SAMPLE,
  SUSPICIOUS_URL_SAMPLE,
} from "./data/sampleData.js";
import { analyzeEmail, analyzeUrl } from "./services/api.js";
import "./App.css";


const EMPTY_EMAIL = {
  sender: "",
  subject: "",
  body: "",
};


function App() {
  const [analysisType, setAnalysisType] = useState("url");
  const [url, setUrl] = useState("");
  const [email, setEmail] = useState(EMPTY_EMAIL);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");


  function selectAnalysisType(type) {
    setAnalysisType(type);
    setResult(null);
    setError("");
  }


  function updateEmail(event) {
    const { name, value } = event.target;

    setEmail((currentEmail) => ({
      ...currentEmail,
      [name]: value,
    }));
  }


  function loadSafeUrl() {
    setAnalysisType("url");
    setUrl(SAFE_URL_SAMPLE);
    setResult(null);
    setError("");
  }


  function loadSuspiciousUrl() {
    setAnalysisType("url");
    setUrl(SUSPICIOUS_URL_SAMPLE);
    setResult(null);
    setError("");
  }


  function loadSuspiciousEmail() {
    setAnalysisType("email");
    setEmail(SUSPICIOUS_EMAIL_SAMPLE);
    setResult(null);
    setError("");
  }


  function clearForm() {
    setUrl("");
    setEmail(EMPTY_EMAIL);
    setResult(null);
    setError("");
  }


  async function submitAnalysis(event) {
    event.preventDefault();

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const analysisResult =
        analysisType === "url"
          ? await analyzeUrl(url)
          : await analyzeEmail(email);

      setResult(analysisResult);
    } catch (requestError) {
      setError(
        requestError.message ||
          "Unable to complete the analysis."
      );
    } finally {
      setLoading(false);
    }
  }


  return (
    <main className="app">
      <header className="hero">
        <p className="eyebrow">
          Cybersecurity Analysis
        </p>

        <h1>Phishing Detection Platform</h1>

        <p className="hero-description">
          Analyze suspicious URLs and email messages using
          explainable, rule-based security checks.
        </p>
      </header>

      <section className="scanner">
        <div className="tabs">
          <button
            className={
              analysisType === "url"
                ? "active"
                : ""
            }
            onClick={() => selectAnalysisType("url")}
            type="button"
          >
            Analyze URL
          </button>

          <button
            className={
              analysisType === "email"
                ? "active"
                : ""
            }
            onClick={() => selectAnalysisType("email")}
            type="button"
          >
            Analyze Email
          </button>
        </div>

        <div className="sample-actions">
          {analysisType === "url" ? (
            <>
              <button
                type="button"
                onClick={loadSafeUrl}
              >
                Try safe URL
              </button>

              <button
                type="button"
                onClick={loadSuspiciousUrl}
              >
                Try suspicious URL
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={loadSuspiciousEmail}
            >
              Try suspicious email
            </button>
          )}

          <button
            type="button"
            onClick={clearForm}
          >
            Clear
          </button>
        </div>

        <form onSubmit={submitAnalysis}>
          {analysisType === "url" ? (
            <label>
              URL to analyze

              <input
                type="url"
                value={url}
                onChange={(event) =>
                  setUrl(event.target.value)
                }
                placeholder="https://example.com/login"
                required
              />
            </label>
          ) : (
            <>
              <label>
                Sender

                <input
                  type="email"
                  name="sender"
                  value={email.sender}
                  onChange={updateEmail}
                  placeholder="security@example.com"
                  required
                />
              </label>

              <label>
                Subject

                <input
                  type="text"
                  name="subject"
                  value={email.subject}
                  onChange={updateEmail}
                  placeholder="Urgent account notice"
                />
              </label>

              <label>
                Email body

                <textarea
                  name="body"
                  value={email.body}
                  onChange={updateEmail}
                  placeholder="Paste the email message here..."
                  rows="8"
                  required
                />
              </label>
            </>
          )}

          <button
            className="analyze-button"
            disabled={loading}
            type="submit"
          >
            {loading
              ? "Analyzing..."
              : "Run Analysis"}
          </button>
        </form>

        {error && (
          <div
            className="error-message"
            role="alert"
          >
            {error}
          </div>
        )}
      </section>

      {result && (
        <section className="results">
          <div className="result-summary">
            <div>
              <span>Risk score</span>
              <strong>
                {result.risk_score}/100
              </strong>
            </div>

            <div>
              <span>Risk level</span>

              <strong
                className={
                  `risk-${result.risk_level.toLowerCase()}`
                }
              >
                {result.risk_level}
              </strong>
            </div>

            <div>
              <span>Findings</span>
              <strong>
                {result.finding_count}
              </strong>
            </div>
          </div>

          <div className="finding-list">
            <h2>Analysis findings</h2>

            {result.findings.length === 0 ? (
              <p className="safe-message">
                No suspicious indicators were detected.
              </p>
            ) : (
              result.findings.map(
                (finding, index) => (
                  <article
                    className="finding-card"
                    key={`${finding.code}-${index}`}
                  >
                    <div className="finding-heading">
                      <h3>{finding.title}</h3>

                      <span
                        className={
                          `severity severity-${finding.severity.toLowerCase()}`
                        }
                      >
                        {finding.severity}
                      </span>
                    </div>

                    <p>{finding.description}</p>

                    <div className="recommendation">
                      <strong>
                        Recommendation
                      </strong>

                      <p>
                        {finding.recommendation}
                      </p>
                    </div>
                  </article>
                )
              )
            )}
          </div>
        </section>
      )}
    </main>
  );
}


export default App;