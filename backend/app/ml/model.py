from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import (
    BRAND_TOKENS,
    RISKY_TLDS,
    SHORTENER_DOMAINS,
    UrlFeatureExtractor,
    is_ip_host,
    lexical_feature_dict,
    normalize_url,
)
from app.ml.training_data import build_training_data
from app.schemas import AnalyzeResponse, Signal, UrlParts


@dataclass
class PhishingModel:
    pipeline: Pipeline | None = None
    training_samples: int = 0

    @property
    def is_ready(self) -> bool:
        return self.pipeline is not None

    def train(self) -> None:
        urls, labels = build_training_data()
        features = FeatureUnion(
            [
                (
                    "char_ngrams",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        lowercase=True,
                        min_df=1,
                    ),
                ),
                (
                    "lexical",
                    Pipeline(
                        [
                            ("extract", UrlFeatureExtractor()),
                            ("scale", StandardScaler(with_mean=False)),
                        ]
                    ),
                ),
            ]
        )

        self.pipeline = Pipeline(
            [
                ("features", features),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1500,
                        class_weight="balanced",
                        random_state=42,
                    ),
                ),
            ]
        )
        self.pipeline.fit(urls, labels)
        self.training_samples = len(urls)

    def info(self) -> dict[str, object]:
        return {
            "name": "Character TF-IDF + lexical URL Logistic Regression",
            "type": "supervised_url_classifier",
            "training_samples": self.training_samples,
            "features": [
                "character n-grams",
                "host/path/query length",
                "subdomain depth",
                "IP host detection",
                "HTTPS detection",
                "suspicious keyword count",
                "brand impersonation tokens",
                "URL shortener detection",
                "risky TLD detection",
                "entropy",
            ],
        }

    def analyze(self, url: str) -> AnalyzeResponse:
        if self.pipeline is None:
            self.train()

        normalized = normalize_url(url)
        probability = float(self.pipeline.predict_proba([normalized])[0][1])
        signals, safe_signals = self._signals(normalized)

        adjusted = self._calibrated_probability(probability, signals, safe_signals)
        prediction = self._prediction(adjusted)
        confidence = max(adjusted, 1 - adjusted)
        parsed = urlparse(normalized)

        return AnalyzeResponse(
            url=url,
            prediction=prediction,
            phishing_probability=round(adjusted, 4),
            confidence=round(confidence, 4),
            verdict=self._verdict(prediction),
            signals=signals,
            safe_signals=safe_signals,
            parts=UrlParts(
                normalized_url=normalized,
                scheme=parsed.scheme,
                host=(parsed.hostname or "").lower(),
                path=parsed.path or "/",
            ),
        )

    def _calibrated_probability(self, raw: float, signals: list[Signal], safe_signals: list[Signal]) -> float:
        risk_push = sum({"low": 0.025, "medium": 0.06, "high": 0.11}[signal.impact] for signal in signals)
        safety_pull = sum({"low": 0.015, "medium": 0.035, "high": 0.06}[signal.impact] for signal in safe_signals)
        return min(max(raw + risk_push - safety_pull, 0.01), 0.99)

    def _prediction(self, probability: float):
        if probability >= 0.72:
            return "dangerous"
        if probability >= 0.42:
            return "suspicious"
        return "safe"

    def _verdict(self, prediction: str) -> str:
        if prediction == "dangerous":
            return "Likely phishing. Do not enter credentials or payment details."
        if prediction == "suspicious":
            return "Suspicious URL. Verify the sender and destination before opening."
        return "Looks low risk based on URL patterns."

    def _signals(self, normalized: str) -> tuple[list[Signal], list[Signal]]:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        path_query = f"{parsed.path}?{parsed.query}".lower()
        features = lexical_feature_dict(normalized)
        parts = [part for part in host.split(".") if part]
        tld = parts[-1] if parts else ""
        signals: list[Signal] = []
        safe: list[Signal] = []

        if is_ip_host(host):
            signals.append(Signal(label="IP address host", detail="The URL uses a raw IP address instead of a domain.", impact="high"))
        if "@" in normalized:
            signals.append(Signal(label="At-symbol redirect trick", detail="The URL contains an @ symbol, often used to hide the real host.", impact="high"))
        if parsed.scheme != "https":
            signals.append(Signal(label="No HTTPS", detail="The URL does not use an encrypted HTTPS scheme.", impact="medium"))
        else:
            safe.append(Signal(label="HTTPS present", detail="The URL uses HTTPS transport.", impact="low"))
        if host in SHORTENER_DOMAINS:
            signals.append(Signal(label="URL shortener", detail="Short links hide the final destination.", impact="medium"))
        if tld in RISKY_TLDS:
            signals.append(Signal(label="High-risk TLD", detail=f"The .{tld} extension is common in disposable phishing campaigns.", impact="medium"))
        if features["subdomain_count"] >= 3:
            signals.append(Signal(label="Deep subdomain chain", detail="Multiple subdomains can be used to impersonate a trusted brand.", impact="medium"))
        if features["suspicious_token_count"] >= 2:
            signals.append(Signal(label="Urgency and account keywords", detail="The URL contains terms commonly used in credential theft pages.", impact="high"))
        if features["hyphen_count"] >= 3 or features["digit_count"] >= 8:
            signals.append(Signal(label="Noisy URL pattern", detail="Many separators or digits can indicate generated phishing infrastructure.", impact="medium"))
        if "xn--" in host:
            signals.append(Signal(label="Punycode domain", detail="Punycode can hide lookalike characters in internationalized domains.", impact="high"))
        if any(brand in host for brand in BRAND_TOKENS) and features["subdomain_count"] > 0:
            signals.append(Signal(label="Brand in subdomain", detail="A brand token appears outside the registered domain.", impact="medium"))
        if len(normalized) > 120:
            signals.append(Signal(label="Very long URL", detail="Long URLs are harder to inspect and are common in phishing lures.", impact="medium"))
        if not path_query.strip("?") and parsed.scheme == "https" and len(parts) <= 3:
            safe.append(Signal(label="Simple URL shape", detail="The URL has a short host and no suspicious path or query.", impact="medium"))
        if features["suspicious_token_count"] == 0 and features["subdomain_count"] <= 1:
            safe.append(Signal(label="Low keyword pressure", detail="No common phishing urgency terms were found.", impact="medium"))

        return signals[:8], safe[:5]


phishing_model = PhishingModel()
