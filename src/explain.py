"""Plain-English reasons for a PhishGuard verdict."""
from __future__ import annotations

from .features import KEYWORDS, get_hostname

MAX_REASONS = 4


def explain(url: str, features: dict[str, float]) -> list[str]:
    """Return up to MAX_REASONS reasons, most important first."""
    reasons: list[str] = []
    if features["has_ip_address"]:
        reasons.append("Host is a raw IP address instead of a domain name")
    if features["has_at_symbol"]:
        reasons.append("Contains '@' which can hide the real destination")
    if not features["uses_https"]:
        reasons.append("Uses HTTP instead of HTTPS")
    n = int(features["suspicious_keyword_count"])
    if n:
        found = [k for k in KEYWORDS if k in url.lower()]
        reasons.append(f"Contains {n} suspicious keyword(s) ({', '.join(found[:3])})")
    if features["has_suspicious_tld"]:
        reasons.append(f"Suspicious top-level domain (.{get_hostname(url).split('.')[-1]})")
    if features["num_subdomains"] >= 3:
        reasons.append(f"Many subdomains ({int(features['num_subdomains'])})")
    if features["num_hyphens"] >= 3:
        reasons.append(f"Many hyphens ({int(features['num_hyphens'])}) in the URL")
    if features["url_length"] > 75:
        reasons.append(f"Unusually long URL ({int(features['url_length'])} characters)")
    return reasons[:MAX_REASONS]
