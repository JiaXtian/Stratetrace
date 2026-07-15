.PHONY: test demo-opaque demo-ecmp demo-realistic

PYTHON := python3
ENV := PYTHONPYCACHEPREFIX=/tmp/stratatrace-pycache PYTHONPATH=src

test:
	$(ENV) $(PYTHON) -m unittest discover -s tests -v

demo-opaque:
	$(ENV) $(PYTHON) -m stratatrace --simulate tests/fixtures/opaque.json --profile fast -m 8 -v opaque.example

demo-ecmp:
	$(ENV) $(PYTHON) -m stratatrace --simulate tests/fixtures/ecmp.json --min-detectable-prob 0.5 --miss-prob 0.25 -m 8 -v ecmp.example

demo-realistic:
	$(ENV) $(PYTHON) -m stratatrace --simulate tests/fixtures/realistic_lossy_mutable.json -m 30 -v baidu-like.example || test $$? -eq 1
