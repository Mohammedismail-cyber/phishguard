"""Generate a SYNTHETIC, balanced phishing/legitimate URL dataset (data/urls.csv)."""
from __future__ import annotations

import csv
import random
from pathlib import Path

SEED = 42
N_PER_CLASS = 1000
NOISE = 0.05
OUT = Path(__file__).parent / "urls.csv"

LEGIT_DOMAINS = ["wikipedia.org", "github.com", "python.org", "bbc.com", "nytimes.com",
                 "stackoverflow.com", "microsoft.com", "apple.com", "amazon.com",
                 "mozilla.org", "who.int", "un.org", "mit.edu", "riarauniversity.ac.ke",
                 "safaricom.co.ke", "kra.go.ke", "coursera.org", "medium.com",
                 "reddit.com", "linkedin.com", "paypal.com", "google.com", "dropbox.com"]
LEGIT_PATHS = ["", "wiki/Cybersecurity", "docs/getting-started", "news/technology",
               "about", "products/laptops", "blog/2026/security-tips", "help/contact",
               "login", "account/settings", "support/secure-your-device", "learn/python"]
BRANDS = ["paypal", "mpesa", "equity", "kcb", "amazon", "apple", "microsoft", "netflix",
          "facebook", "google", "dropbox", "safaricom"]
WORDS = ["secure", "login", "verify", "account", "update", "banking", "confirm",
         "password", "signin", "wallet"]
BAD_TLDS = ["xyz", "top", "tk", "click", "work", "zip", "gq", "ml", "com", "net", "info"]


def legit(rng: random.Random) -> str:
    """Build one realistic legitimate-looking URL."""
    host = rng.choice(LEGIT_DOMAINS)
    if rng.random() < 0.5:
        host = "www." + host
    elif rng.random() < 0.15:
        host = rng.choice(["docs", "mail", "support", "blog"]) + "." + host
    scheme = "https" if rng.random() < 0.93 else "http"
    path = rng.choice(LEGIT_PATHS)
    return f"{scheme}://{host}/{path}".rstrip("/") if not path else f"{scheme}://{host}/{path}"


def phish(rng: random.Random) -> str:
    """Build one realistic phishing-looking URL."""
    kind = rng.random()
    scheme = "http" if rng.random() < 0.72 else "https"
    path = "/".join(rng.choice(WORDS + ["index.php", "form", "id" + str(rng.randint(10, 9999))])
                    for _ in range(rng.randint(0, 4)))
    if kind < 0.18:  # raw IP host
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{path}"
    if kind < 0.30:  # '@' trick
        return f"{scheme}://{rng.choice(LEGIT_DOMAINS)}@{rng.choice(BRANDS)}-{rng.choice(WORDS)}.{rng.choice(BAD_TLDS)}/{path}"
    if kind < 0.65:  # hyphenated brand + keywords
        parts = [rng.choice(WORDS), rng.choice(BRANDS)] + [rng.choice(WORDS) for _ in range(rng.randint(0, 2))]
        return f"{scheme}://{'-'.join(parts)}.{rng.choice(BAD_TLDS)}/{path}"
    # many-subdomain lookalike
    subs = ".".join(rng.choice(WORDS + BRANDS) for _ in range(rng.randint(2, 4)))
    return f"{scheme}://{subs}.{rng.choice(['com', 'net', 'info', 'xyz', 'top'])}/{path}"


def main() -> None:
    """Write urls.csv with label noise so the task is not trivially separable."""
    rng = random.Random(SEED)
    rows = [(legit(rng), 0) for _ in range(N_PER_CLASS)] + [(phish(rng), 1) for _ in range(N_PER_CLASS)]
    rows = [(u, (1 - y) if rng.random() < NOISE else y) for u, y in rows]
    rng.shuffle(rows)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
