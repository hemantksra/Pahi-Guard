export type RiskLevel = "safe" | "suspicious" | "dangerous";

export interface Signal {
  label: string;
  detail: string;
  impact: "low" | "medium" | "high";
}

export interface UrlParts {
  normalized_url: string;
  scheme: string;
  host: string;
  path: string;
}

export interface AnalyzeResponse {
  url: string;
  prediction: RiskLevel;
  phishing_probability: number;
  confidence: number;
  verdict: string;
  signals: Signal[];
  safe_signals: Signal[];
  parts: UrlParts;
}

export interface ModelInfo {
  name: string;
  type: string;
  training_samples: number;
  features: string[];
}
