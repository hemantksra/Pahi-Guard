from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable
from urllib.parse import urlparse

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin

SUSPICIOUS_TOKENS = {
    "account",
    "banking",
    "confirm",
    "free",
    "gift",
    "invoice",
    "limited",
    "login",
    "password",
    "payment",
    "prize",
    "recover",
    "refund",
    "secure",
    "signin",
    "support",
    "suspended",
    "unlock",
    "update",
    "urgent",
    "verify",
    "wallet",
    "win",
}

BRAND_TOKENS = {
    "amazon",
    "apple",
    "axisbank",
    "facebook",
    "google",
    "hdfcbank",
    "icici",
    "instagram",
    "microsoft",
    "netflix",
    "paypal",
    "sbi",
    "spotify",
    "whatsapp",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "tinyurl.com",
    "t.co",
}

RISKY_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "support", "live", "quest"}


def normalize_url(url: str) -> str:
    value = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"https://{value}"
    return value


def parse_url(url: str):
    return urlparse(normalize_url(url))


def hostname(url: str) -> str:
    parsed = parse_url(url)
    return (parsed.hostname or "").lower()


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))


def count_tokens(value: str, tokens: Iterable[str]) -> int:
    lowered = value.lower()
    return sum(1 for token in tokens if token in lowered)


def registered_domain_parts(host: str) -> list[str]:
    return [part for part in host.split(".") if part]


def lexical_feature_dict(url: str) -> dict[str, float]:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    parts = registered_domain_parts(host)
    tld = parts[-1] if parts else ""
    subdomain_count = max(len(parts) - 2, 0)
    brand_hits = count_tokens(host, BRAND_TOKENS)
    suspicious_hits = count_tokens(normalized, SUSPICIOUS_TOKENS)

    return {
        "url_length": float(len(normalized)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "dot_count": float(normalized.count(".")),
        "hyphen_count": float(normalized.count("-")),
        "digit_count": float(sum(char.isdigit() for char in normalized)),
        "slash_count": float(normalized.count("/")),
        "at_symbol": float("@" in normalized),
        "https": float(parsed.scheme == "https"),
        "ip_host": float(is_ip_host(host)),
        "subdomain_count": float(subdomain_count),
        "suspicious_token_count": float(suspicious_hits),
        "brand_token_count": float(brand_hits),
        "shortener": float(host in SHORTENER_DOMAINS),
        "risky_tld": float(tld in RISKY_TLDS),
        "punycode": float("xn--" in host),
        "entropy": float(shannon_entropy(normalized)),
    }


class UrlFeatureExtractor(BaseEstimator, TransformerMixin):
    feature_names = [
        "url_length",
        "host_length",
        "path_length",
        "query_length",
        "dot_count",
        "hyphen_count",
        "digit_count",
        "slash_count",
        "at_symbol",
        "https",
        "ip_host",
        "subdomain_count",
        "suspicious_token_count",
        "brand_token_count",
        "shortener",
        "risky_tld",
        "punycode",
        "entropy",
    ]

    def fit(self, urls, y=None):
        return self

    def transform(self, urls):
        rows = []
        for url in urls:
            features = lexical_feature_dict(str(url))
            rows.append([features[name] for name in self.feature_names])
        return sparse.csr_matrix(np.asarray(rows, dtype=float))
