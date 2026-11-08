"""Lexical feature extraction for PhishGuard. URLs are never fetched."""
from __future__ import annotations

import re
from urllib.parse import urlparse

FEATURE_NAMES: list[str] = [
    "url_length", "hostname_length", "num_dots", "num_hyphens", "num_digits",
    "has_at_symbol", "has_ip_address", "uses_https", "num_subdomains",
    "path_depth", "suspicious_keyword_count", "has_suspicious_tld",
]
KEYWORDS = ["login", "verify", "secure", "account", "update", "banking",
            "confirm", "password", "signin", "wallet"]
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "click", "work", "gq", "ml", "cf"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse(url: str):
    """Parse a URL safely, adding a scheme if missing. Never raises."""
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url
    try:
        return url, urlparse(url)
    except ValueError:
        return url, urlparse("http://invalid")


def get_hostname(url: str) -> str:
    """Return the lowercase hostname (no credentials or port)."""
    raw, parsed = _parse(url)
    try:
        host = parsed.hostname or ""
    except ValueError:
        host = ""
    if not host:  # fallback for malformed input
        host = raw.split("://", 1)[-1].split("/")[0].split("@")[-1].split(":")[0]
    return host.lower()


def extract_features(url: str) -> dict[str, float]:
    """Extract the 12 lexical features from a URL string."""
    raw, parsed = _parse(url)
    host = get_hostname(url)
    lowered = raw.lower()
    is_ip = bool(_IPV4.match(host))
    labels = [p for p in host.split(".") if p]
    path_segments = [s for s in (parsed.path or "").split("/") if s]
    tld = labels[-1] if labels else ""
    return {
        "url_length": float(len(raw)),
        "hostname_length": float(len(host)),
        "num_dots": float(raw.count(".")),
        "num_hyphens": float(raw.count("-")),
        "num_digits": float(sum(c.isdigit() for c in raw)),
        "has_at_symbol": float("@" in raw),
        "has_ip_address": float(is_ip),
        "uses_https": float(lowered.startswith("https://")),
        "num_subdomains": 0.0 if is_ip else float(max(len(labels) - 2, 0)),
        "path_depth": float(len(path_segments)),
        "suspicious_keyword_count": float(sum(lowered.count(k) for k in KEYWORDS)),
        "has_suspicious_tld": float(tld in SUSPICIOUS_TLDS),
    }


def features_to_vector(url: str) -> list[float]:
    """Return feature values in the fixed FEATURE_NAMES order."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]
