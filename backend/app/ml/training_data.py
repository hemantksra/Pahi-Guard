from __future__ import annotations

import random

LEGITIMATE_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.in",
    "flipkart.com",
    "netflix.com",
    "spotify.com",
    "github.com",
    "linkedin.com",
    "paypal.com",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "sbi.co.in",
    "phonepe.com",
    "razorpay.com",
    "zerodha.com",
    "stackoverflow.com",
    "wikipedia.org",
    "openai.com",
]

PHISHING_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "apple",
    "netflix",
    "hdfcbank",
    "axisbank",
    "icici",
    "sbi",
    "instagram",
    "facebook",
    "whatsapp",
]

SUSPICIOUS_WORDS = [
    "verify",
    "secure",
    "login",
    "signin",
    "account",
    "update",
    "unlock",
    "support",
    "payment",
    "refund",
    "limited",
    "urgent",
]

PHISHING_TLDS = ["click", "top", "xyz", "live", "support", "work", "quest", "zip"]
SAFE_PATHS = ["", "about", "help", "pricing", "careers", "docs", "blog", "security", "contact"]


def build_training_data(seed: int = 42) -> tuple[list[str], list[int]]:
    rng = random.Random(seed)
    urls: list[str] = []
    labels: list[int] = []

    for domain in LEGITIMATE_DOMAINS:
        for _ in range(12):
            scheme = rng.choice(["https", "https", "https", "http"])
            subdomain = rng.choice(["", "www.", "accounts.", "support.", "developer."])
            path = rng.choice(SAFE_PATHS)
            suffix = f"/{path}" if path else ""
            query = rng.choice(["", "", "?ref=home", "?utm_source=search"])
            urls.append(f"{scheme}://{subdomain}{domain}{suffix}{query}")
            labels.append(0)

    for brand in PHISHING_BRANDS:
        for _ in range(18):
            words = rng.sample(SUSPICIOUS_WORDS, k=3)
            separator = rng.choice(["-", ".", ""])
            fake_domain = separator.join([brand, *words[:2]])
            tld = rng.choice(PHISHING_TLDS)
            path_token = rng.choice(SUSPICIOUS_WORDS)
            digits = rng.randint(1000, 999999)
            urls.append(
                f"http://{fake_domain}.{tld}/{path_token}/{brand}/session?id={digits}&token={rng.randint(10000, 99999)}"
            )
            labels.append(1)

            host = f"{brand}.{words[0]}.{words[1]}.{rng.choice(['security', 'service', 'center'])}.{tld}"
            urls.append(f"https://{host}/login/confirm-password")
            labels.append(1)

    ip_hosts = ["185.14.29.41", "91.210.107.88", "45.77.129.201", "103.22.190.12"]
    for ip in ip_hosts:
        for word in SUSPICIOUS_WORDS:
            urls.append(f"http://{ip}/{word}/account/verify")
            labels.append(1)

    shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "t.co"]
    for domain in shorteners:
        for _ in range(20):
            urls.append(f"https://{domain}/{rng.choice(['a', 'go', 'pay', 'secure'])}{rng.randint(10000, 999999)}")
            labels.append(1)

    combined = list(zip(urls, labels))
    rng.shuffle(combined)
    shuffled_urls, shuffled_labels = zip(*combined)
    return list(shuffled_urls), list(shuffled_labels)
