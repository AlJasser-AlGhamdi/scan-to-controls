export PYTHONHASHSEED := 0
UV ?= uv

.DEFAULT_GOAL := help

help:
	@echo "Targets: install test reproduce robustness"

install:
	$(UV) sync --locked

test:
	$(UV) run pytest -m "not integration and not e2e"

reproduce:
	$(UV) run python evaluation/run_evaluation.py --reproduce

robustness:
	$(UV) run python evaluation/run_evaluation.py --robustness
	cp evaluation/outputs/robustness.json evaluation/robustness.json

.PHONY: help install test reproduce robustness
