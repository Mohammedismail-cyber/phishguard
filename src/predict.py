"""PhishGuard command-line predictor. Static analysis only; URLs are never visited."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib

from .explain import explain
from .features import extract_features, features_to_vector

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishguard_model.joblib"
THRESHOLD = 0.5
RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"


def load_model(path: Path = MODEL_PATH):
    """Load the trained model, or return None if it does not exist."""
    return joblib.load(path) if Path(path).exists() else None


def analyse(url: str, model) -> dict:
    """Score one URL and return verdict, probability and reasons."""
    prob = float(model.predict_proba([features_to_vector(url)])[0][1])
    feats = extract_features(url)
    return {"url": url, "verdict": "SUSPICIOUS" if prob >= THRESHOLD else "SAFE",
            "risk_score": round(prob, 2), "reasons": explain(url, feats)}


def render(res: dict) -> str:
    """Format a result as coloured text."""
    colour = RED if res["verdict"] == "SUSPICIOUS" else GREEN
    lines = [f"URL: {res['url']}", f"Verdict: {colour}{res['verdict']}{RESET}",
             f"Risk score: {res['risk_score']:.2f}"]
    if res["reasons"]:
        lines.append("Reasons:")
        lines += [f"  - {r}" for r in res["reasons"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    ap = argparse.ArgumentParser(description="PhishGuard phishing URL detector")
    ap.add_argument("url", nargs="?", help="URL to analyse")
    ap.add_argument("--file", help="text file with one URL per line")
    ap.add_argument("--json", action="store_true", help="output JSON (no colour)")
    args = ap.parse_args(argv)

    model = load_model()
    if model is None:
        print("Model not found. Please run 'make data' and 'make train' first.")
        return 1
    urls = [args.url] if args.url else []
    if args.file:
        urls += [l.strip() for l in Path(args.file).read_text().splitlines() if l.strip()]
    if not urls:
        ap.print_usage()
        return 2
    results = [analyse(u, model) for u in urls]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n".join(render(r) for r in results), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
