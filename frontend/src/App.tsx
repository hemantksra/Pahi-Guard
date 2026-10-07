import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ClipboardCheck,
  Globe2,
  History,
  Link2,
  Loader2,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UploadCloud,
  XCircle
} from "lucide-react";
import { analyzeBatch, analyzeUrl, getModelInfo } from "./api";
import type { AnalyzeResponse, ModelInfo, RiskLevel, Signal } from "./types";

const examples = [
  "https://www.github.com/security",
  "http://paypal-secure-login.verify-account.click/login/confirm",
  "https://bit.ly/pay883912",
  "https://www.hdfcbank.com/personal/pay"
];

const riskCopy: Record<RiskLevel, { label: string; icon: typeof ShieldCheck }> = {
  safe: { label: "Safe", icon: ShieldCheck },
  suspicious: { label: "Suspicious", icon: ShieldAlert },
  dangerous: { label: "Dangerous", icon: ShieldAlert }
};

function App() {
  const [url, setUrl] = useState(examples[1]);
  const [batchText, setBatchText] = useState(examples.join("\n"));
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [batchResults, setBatchResults] = useState<AnalyzeResponse[]>([]);
  const [history, setHistory] = useState<AnalyzeResponse[]>([]);
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [batchLoading, setBatchLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getModelInfo().then(setModelInfo).catch(() => undefined);
  }, []);

  const score = Math.round((result?.phishing_probability ?? 0) * 100);
  const riskClass = result?.prediction ?? "suspicious";

  const dominantSignals = useMemo(() => {
    if (!result) return [];
    return [...result.signals, ...result.safe_signals].slice(0, 6);
  }, [result]);

  async function handleScan(nextUrl = url) {
    if (!nextUrl.trim()) return;
    setLoading(true);
    setError("");
    try {
      const response = await analyzeUrl(nextUrl.trim());
      setResult(response);
      setHistory((current) => [response, ...current.filter((item) => item.url !== response.url)].slice(0, 8));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to analyze URL");
    } finally {
      setLoading(false);
    }
  }

  async function handleBatch() {
    const urls = batchText
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 25);
    if (!urls.length) return;

    setBatchLoading(true);
    setError("");
    try {
      const response = await analyzeBatch(urls);
      setBatchResults(response.results);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to analyze batch");
    } finally {
      setBatchLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero-band">
        <nav className="topbar">
          <div className="brand">
            <span className="brand-mark"><Shield size={22} /></span>
            <span>Pahi-Guard</span>
          </div>
          <div className="status-pill">
            <Activity size={16} />
            <span>{modelInfo ? `${modelInfo.training_samples} samples trained` : "Model loading"}</span>
          </div>
        </nav>

        <div className="hero-grid">
          <div className="hero-copy">
            <span className="eyebrow"><Radar size={16} /> URL phishing detection</span>
            <h1>Pahi-Guard</h1>
            <p>
              Scan suspicious links with a URL-trained machine learning model and see the exact signals behind every verdict.
            </p>
            <div className="hero-actions">
              <button className="primary-action" onClick={() => handleScan()} disabled={loading}>
                {loading ? <Loader2 className="spin" size={18} /> : <Search size={18} />}
                Analyze URL
              </button>
              <button className="secondary-action" onClick={handleBatch} disabled={batchLoading}>
                {batchLoading ? <Loader2 className="spin" size={18} /> : <UploadCloud size={18} />}
                Batch Scan
              </button>
            </div>
          </div>

          <div className="scanner-panel">
            <label htmlFor="url-input">URL</label>
            <div className="input-row">
              <Link2 size={20} />
              <input
                id="url-input"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                onKeyDown={(event) => event.key === "Enter" && handleScan()}
                placeholder="https://example.com/login"
              />
              <button aria-label="Analyze URL" onClick={() => handleScan()} disabled={loading}>
                {loading ? <Loader2 className="spin" size={18} /> : <Search size={18} />}
              </button>
            </div>
            <div className="example-row">
              {examples.map((item) => (
                <button
                  key={item}
                  onClick={() => {
                    setUrl(item);
                    handleScan(item);
                  }}
                >
                  {new URL(item).hostname.replace("www.", "")}
                </button>
              ))}
            </div>
            {error && <div className="error-banner"><XCircle size={16} /> {error}</div>}
          </div>
        </div>
      </section>

      <section className="dashboard-grid">
        <div className={`verdict-panel ${riskClass}`}>
          <div className="panel-title">
            <span><BarChart3 size={18} /> Risk verdict</span>
            {result && <span className="tiny-tag">{Math.round(result.confidence * 100)}% confidence</span>}
          </div>

          <div className="gauge-wrap">
            <div className="gauge" style={{ "--score": `${score}%` } as React.CSSProperties}>
              <div className="gauge-core">
                <span>{result ? score : "--"}</span>
                <small>risk score</small>
              </div>
            </div>
            <div className="verdict-copy">
              {result ? (
                <>
                  <RiskBadge level={result.prediction} />
                  <p>{result.verdict}</p>
                  <code>{result.parts.host || result.parts.normalized_url}</code>
                </>
              ) : (
                <>
                  <RiskBadge level="suspicious" />
                  <p>Run a scan to generate a verdict.</p>
                  <code>No URL analyzed yet</code>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="signals-panel">
          <div className="panel-title">
            <span><AlertTriangle size={18} /> Detection signals</span>
            <span className="tiny-tag">{dominantSignals.length} shown</span>
          </div>
          <div className="signal-list">
            {dominantSignals.length ? (
              dominantSignals.map((signal) => <SignalRow key={`${signal.label}-${signal.detail}`} signal={signal} />)
            ) : (
              <div className="empty-state">
                <Sparkles size={22} />
                <span>Signals appear after the first scan.</span>
              </div>
            )}
          </div>
        </div>

        <div className="model-panel">
          <div className="panel-title">
            <span><Globe2 size={18} /> Model profile</span>
            <span className="tiny-tag">URL only</span>
          </div>
          <h2>{modelInfo?.name ?? "Character TF-IDF + lexical URL Logistic Regression"}</h2>
          <div className="feature-cloud">
            {(modelInfo?.features ?? ["character n-grams", "subdomain depth", "suspicious keywords", "URL entropy"]).map((feature) => (
              <span key={feature}>{feature}</span>
            ))}
          </div>
        </div>

        <div className="batch-panel">
          <div className="panel-title">
            <span><ClipboardCheck size={18} /> Batch scanner</span>
            <span className="tiny-tag">25 max</span>
          </div>
          <textarea value={batchText} onChange={(event) => setBatchText(event.target.value)} />
          <button className="full-action" onClick={handleBatch} disabled={batchLoading}>
            {batchLoading ? <Loader2 className="spin" size={18} /> : <UploadCloud size={18} />}
            Analyze List
          </button>
        </div>

        <div className="batch-results-panel">
          <div className="panel-title">
            <span><History size={18} /> Recent scans</span>
            <span className="tiny-tag">{history.length || batchResults.length} items</span>
          </div>
          <div className="table-list">
            {(batchResults.length ? batchResults : history).map((item) => (
              <button key={`${item.url}-${item.phishing_probability}`} onClick={() => setResult(item)}>
                <span className={`dot ${item.prediction}`} />
                <span className="table-url">{item.parts.host || item.url}</span>
                <strong>{Math.round(item.phishing_probability * 100)}%</strong>
              </button>
            ))}
            {!batchResults.length && !history.length && (
              <div className="empty-state">
                <History size={22} />
                <span>Scanned URLs will stay here.</span>
              </div>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}

function RiskBadge({ level }: { level: RiskLevel }) {
  const Icon = riskCopy[level].icon;
  return (
    <span className={`risk-badge ${level}`}>
      <Icon size={18} />
      {riskCopy[level].label}
    </span>
  );
}

function SignalRow({ signal }: { signal: Signal }) {
  const Icon = signal.impact === "high" ? AlertTriangle : signal.impact === "medium" ? ShieldAlert : CheckCircle2;
  return (
    <div className={`signal-row ${signal.impact}`}>
      <Icon size={18} />
      <div>
        <strong>{signal.label}</strong>
        <span>{signal.detail}</span>
      </div>
    </div>
  );
}

export default App;
