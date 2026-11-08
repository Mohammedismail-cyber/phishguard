.PHONY: install data train test demo
PY ?= python

install:
	$(PY) -m pip install -r requirements.txt

data:
	$(PY) data/build_dataset.py

train:
	$(PY) -m src.train

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m src.predict "https://www.wikipedia.org/wiki/Cybersecurity"
	$(PY) -m src.predict "http://secure-login-paypal.verify-account.xyz/signin"
	$(PY) -m src.predict "http://192.168.44.12/bank/update/confirm/login.php"
