"""Train and evaluate PhishGuard; save model, metrics and figures."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_NAMES, features_to_vector

SEED = 42
ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishguard_model.joblib"
FIG_DIR = ROOT / "docs" / "figures"
METRICS_PATH = ROOT / "docs" / "metrics.json"


def scores(y_true, y_pred) -> dict[str, float]:
    """Compute accuracy, precision, recall and F1."""
    return {"accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred),
            "recall": recall_score(y_true, y_pred),
            "f1": f1_score(y_true, y_pred)}


def main() -> None:
    """Run the full training pipeline."""
    ap = argparse.ArgumentParser(description="Train PhishGuard")
    ap.add_argument("--input", default=str(ROOT / "data" / "urls.csv"), help="CSV with url,label")
    args = ap.parse_args()

    df = pd.read_csv(args.input).dropna()
    X = np.array([features_to_vector(u) for u in df["url"]])
    y = df["label"].astype(int).to_numpy()
    X_tr, X_te, y_tr, y_te, _, url_te = train_test_split(
        X, y, df["url"].to_numpy(), test_size=0.2, stratify=y, random_state=SEED)

    rf = RandomForestClassifier(n_estimators=200, random_state=SEED).fit(X_tr, y_tr)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=SEED)).fit(X_tr, y_tr)
    results = {"random_forest": scores(y_te, rf.predict(X_te)),
               "logistic_regression": scores(y_te, lr.predict(X_te))}
    print(f"{'Model':<22}{'Acc':>8}{'Prec':>8}{'Rec':>8}{'F1':>8}")
    for name, m in results.items():
        print(f"{name:<22}{m['accuracy']:>8.3f}{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}")

    best_name = max(results, key=lambda k: results[k]["f1"])
    best = rf if best_name == "random_forest" else lr
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(best, MODEL_PATH)

    # Average end-to-end prediction time (feature extraction + inference), per URL.
    sample = list(url_te[:200])
    t0 = time.perf_counter()
    for u in sample:
        best.predict_proba([features_to_vector(u)])
    avg_ms = (time.perf_counter() - t0) * 1000 / len(sample)

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    pred = best.predict(X_te)
    fig, ax = plt.subplots(figsize=(5, 4.5))
    disp = ConfusionMatrixDisplay.from_predictions(y_te, pred, display_labels=["Legitimate", "Phishing"],
                                                   cmap="Blues", ax=ax, colorbar=False)
    cm = disp.confusion_matrix
    for (i, j), txt in np.ndenumerate(disp.text_):
        txt.set_color("white" if cm[i, j] > cm.max() / 2 else "black")
        txt.set_fontsize(16)
    ax.set_title(f"Confusion Matrix ({best_name.replace('_', ' ').title()})")
    fig.tight_layout(); fig.savefig(FIG_DIR / "confusion_matrix.png", dpi=150); plt.close(fig)

    importances = rf.feature_importances_
    order = np.argsort(importances)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh([FEATURE_NAMES[i] for i in order], importances[order], color="#2b6cb0")
    ax.set_xlabel("Importance (Random Forest)"); ax.set_title("Feature Importance")
    fig.tight_layout(); fig.savefig(FIG_DIR / "feature_importance.png", dpi=150); plt.close(fig)

    proba = best.predict_proba(X_te)[:, 1]
    fpr, tpr, _ = roc_curve(y_te, proba)
    auc = roc_auc_score(y_te, proba)
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    ax.plot(fpr, tpr, color="#2b6cb0", lw=2, label=f"AUC = {auc:.3f}")
    ax.plot([0, 1], [0, 1], "--", color="grey", label="Chance")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve"); ax.legend(loc="lower right")
    fig.tight_layout(); fig.savefig(FIG_DIR / "roc_curve.png", dpi=150); plt.close(fig)

    out = {"best_model": best_name, "n_samples": int(len(df)), "n_test": int(len(y_te)),
           "n_features": len(FEATURE_NAMES), "roc_auc": float(auc),
           "avg_prediction_ms": avg_ms, **{k: float(v) for k, v in results[best_name].items()},
           "all_models": {k: {a: float(b) for a, b in v.items()} for k, v in results.items()},
           "feature_importance": {FEATURE_NAMES[i]: float(importances[i]) for i in np.argsort(-importances)}}
    METRICS_PATH.write_text(json.dumps(out, indent=2))
    print(f"\nBest model: {best_name} | avg prediction: {avg_ms:.2f} ms/URL")
    print(f"Saved model -> {MODEL_PATH}\nSaved metrics -> {METRICS_PATH}")


if __name__ == "__main__":
    main()
