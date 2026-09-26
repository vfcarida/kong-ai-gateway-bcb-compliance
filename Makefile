.PHONY: help test test-lua test-e2e up-oss up-enterprise down restart logs status clean format lint certs certs-verify

PYTHON ?= python
PYTEST ?= pytest

help:
	@echo "Kong AI Gateway (BCB CMN 4.893/21 & BCB 85/21 Compliance) - Developer Commands:"
	@echo "  make up-oss          Start Open Source stack (Kong OSS, PII Sanitizer, OTel Collector)"
	@echo "  make up-enterprise   Start Enterprise overlay stack (requires Kong Enterprise license)"
	@echo "  make down            Stop all running containers and teardown networks"
	@echo "  make restart         Restart all running containers"
	@echo "  make logs            Follow container logs in real time"
	@echo "  make status          Show status of active containers and healthchecks"
	@echo "  make test            Run Python unit and integration test suite (FastAPI, PII, TLS)"
	@echo "  make test-lua        Run Kong custom plugin Lua Busted specifications via Pongo"
	@echo "  make test-e2e        Execute end-to-end proxy verification script"
	@echo "  make certs           Generate ephemeral self-signed dev TLS certificates"
	@echo "  make certs-verify    Verify validity and SANs of dev-cert.pem"
	@echo "  make lint            Run static analysis and linting checks"
	@echo "  make format          Auto-format Python codebases"
	@echo "  make clean           Clean up local caches and temporary artifacts"

up-oss:
	docker compose --profile oss up -d

up-enterprise:
	docker compose --profile enterprise up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

status:
	docker compose ps

test:
	$(PYTEST) pii-sanitizer/tests/ -v

test-lua:
	pongo run spec/

test-e2e:
	$(PYTHON) test_kong_proxy.py --prompt "Teste de transferencia para CPF 123.456.789-09"

certs:
	$(PYTHON) scripts/generate_dev_certs.py

certs-verify:
	$(PYTHON) scripts/generate_dev_certs.py --verify

lint:
	$(PYTHON) -m flake8 pii-sanitizer/ test_kong_proxy.py || true

format:
	$(PYTHON) -m black pii-sanitizer/ test_kong_proxy.py || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov 2>/dev/null || true
