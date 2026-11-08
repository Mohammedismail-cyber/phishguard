from pathlib import Path

import pytest

from src import predict
from src.predict import analyse, load_model, main

needs_model = pytest.mark.skipif(load_model() is None, reason="run make train first")


@needs_model
def test_phishing_scores_higher_than_legit():
    model = load_model()
    bad = analyse("http://secure-login-paypal.verify-account.xyz/signin", model)
    good = analyse("https://www.wikipedia.org/wiki/Cybersecurity", model)
    assert bad["risk_score"] > good["risk_score"]
    assert bad["verdict"] == "SUSPICIOUS" and good["verdict"] == "SAFE"


@needs_model
def test_cli_exit_code_zero():
    assert main(["https://www.python.org"]) == 0


def test_missing_model_handled(monkeypatch, capsys):
    monkeypatch.setattr(predict, "MODEL_PATH", Path("/nonexistent/model.joblib"))
    monkeypatch.setattr(predict, "load_model", lambda path=Path("/nonexistent"): None)
    assert main(["http://x.com"]) == 1
    assert "make train" in capsys.readouterr().out
