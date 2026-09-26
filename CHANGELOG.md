# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Adversarial & PII Edge-Case Fuzzing Suite (TEST-02)**: Added comprehensive edge-case test suite (`pii-sanitizer/tests/test_adversarial_fuzzing.py`) verifying modulo-11 check-digit edge cases (all repeated sequences `000...` through `999...`), zero-width/invisible Unicode characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u00A0`), homoglyphs/confusables, irregular whitespaces/tabs, large payloads, and RFC 7807 problem details contract compliance.
- **Comprehensive Documentation & Reference Specifications (DOC-01)**: Created in-depth guides and API references in `docs/`:
  - `docs/guides/getting-started.md`: Local deployment, Docker Compose execution, and curl verification.
  - `docs/guides/production-hardening.md`: Enterprise architecture, mTLS, RBAC, WORM audit log retention, and secret vaults.
  - `docs/guides/bcb-regulatory-mapping.md`: Exhaustive article-by-article regulatory cross-walk covering CMN 4.893/2021, BCB 85/2021, and LGPD.
  - `docs/reference/plugin-configuration.md`: Parameter reference and schemas for `bcb-pii-sanitizer` and `bcb-otel-scrubber`.
  - `docs/reference/api-specification.md`: OpenAPI 3.1 specification for the `pii-sanitizer` microservice.
- **Automated Dev TLS Certificate Generator (SEC-01 / TECH-03)**: Added cross-platform certificate generation script (`scripts/generate_dev_certs.py`) powered by pure-Python `cryptography` library to create ephemeral RSA keys and X.509 v3 certificates with Subject Alternative Names (`localhost`, `pii-sanitizer`, `127.0.0.1`) on demand. Added `make certs` and `make certs-verify` targets, along with comprehensive secret management and rotation guidance in `SECURITY.md`.
- **Production Mock LLM Disable Guard (TEST-03 / TECH-02)**: Added `ENABLE_MOCK_LLM` environment variable guard in `pii-sanitizer/app/main.py`. When set to `false`, all `/mock-llm` routes (`/v1/chat/completions`, `/last-request`, `/reset`) are locked down and return RFC 7807 404 Problem Details to prevent development mock routes and in-memory payloads from being exposed in production environments.
- **Production Kubernetes Deployment Manifests (FEAT-04)**: Provided complete declarative Kubernetes manifests under `k8s/` using Kustomize (`kubectl apply -k k8s/`), including `KongPlugin` CRDs for `bcb-pii-sanitizer` and `bcb-otel-scrubber`, hardened `Deployment` and `ClusterIP` Service for `pii-sanitizer` (with non-root `securityContext`), OpenTelemetry Collector Contrib with span redaction ConfigMap, and Ingress routing rules.
- **Defensive Checksum Validation**: Guarded `validate_cpf_digits` and `validate_cnpj_digits` against non-digit inputs with `.isdigit()` checks.
- **Flexible Whitespace in Money Pattern**: Updated MONEY regex in `pii_engine.py` to support variable spaces/tabs between currency symbol and amount.

## [2.1.0] — 2026-09-21

### Added
- **Session-Consistent Synthetic Pseudonymization (IMP-009)**: Repeated occurrences of the same PII entity within a single prompt or across multi-turn conversation sessions (`session_id`) now receive identical synthetic replacements, preserving LLM referential integrity (`pii-sanitizer/app/pii_engine.py`, `pii-sanitizer/app/main.py`).
- **Format-Aware Synthetic Output**: Raw and formatted representations of the same CPF/CNPJ (e.g., `12345678909` vs `123.456.789-09`) are assigned consistent synthetic values while preserving their original formatting style (`pii_engine._format_synthetic`).
- **Canonical Entity Key Normalization** (`normalize_entity_key`): Deterministic key strategy stripping formatting, normalizing case, and canonicalizing entity values before synthetic assignment.
- **Optional `session_id` in `/sanitize` API**: Allows callers to opt-in to cross-turn synthetic identity persistence for conversational LLM sessions.
- **ADR 0003**: Architecture Decision Record documenting the synthetic pseudonymization design and its trade-offs (`docs/adr/0003-session-consistent-synthetic-pseudonymization.md`).
- **Makefile**: Developer experience shortcut commands: `make test`, `make up-oss`, `make up-enterprise`, `make lint`, `make format`, `make clean` and more.
- **`.pre-commit-config.yaml`**: Pre-commit hooks for `black`, `flake8`, and general hygiene checks.
- **GitHub Issue and PR Templates**: Standardized community contribution templates under `.github/`.
- **`CHANGELOG.md`** (this file): Initiated changelog tracking for the project.
- 3 new pytest tests for synthetic consistency (total: **42 passing**).

### Changed
- **CONTRIBUTING.md**: Updated developer tooling section to document Makefile usage and pre-commit hook installation. Updated test count to 42+.
- **Dockerfile** (`pii-sanitizer/Dockerfile`): Version label updated to `2.0.0` to align with `main.py` and `schemas.py`.

### Fixed
- Synthetic PII entities are no longer randomly inconsistent across multiple occurrences of the same entity in a single prompt.

---

## [2.0.0] — 2026-09-18

### Added
- **Fail-Closed PII Sanitization (KAG-T02)**: Default `fail_open=false` in schema and `config/kong.yaml`; Kong returns RFC 7807 502 Bad Gateway on sanitizer degradation instead of silently forwarding unsanitized prompts.
- **Checksum-Gated CPF/CNPJ Detection (KAG-T03)**: Raw 11-digit numbers that fail CPF Modulus-11 checksum are no longer treated as CPF (eliminating order-number false positives). Matching improvements for bank account, money, and phone regexes.
- **Full Role & Content Coverage (KAG-T04)**: `handler.lua` now scans all message roles (not just `user`) and handles OpenAI array `content` parts (`{type="text", text=...}`).
- **OSS vs. Enterprise Docker Compose Profiles (KAG-T05)**: Separate `oss` and `enterprise` profiles; OSS runs 100% license-free on `kong:3.14`; Enterprise activates `ai-semantic-cache` and `ai-rate-limiting-advanced`.
- **Dual-Tier OTel Privacy Pipeline (KAG-T06)**: Real OTLP span export via `opentelemetry` plugin + OTel Collector `attributes/redact_genai` processor; `bcb-otel-scrubber` handles Kong log serialization.
- **Admin Plane & TLS Hardening (KAG-T07)**: Admin API and GUI bound to loopback `127.0.0.1` only; Kong ↔ Sanitizer communication encrypted over TLS (`https://pii-sanitizer:8443`).
- **Defensible Compliance Documentation (KAG-T08)**: Removed all unqualified compliance guarantees; added legal framing, accurate CMN 4.893/2021 (amended by CMN 5.274/2025) and BCB 85/2021 citations.
- **Open-Source Governance (IMP-008)**: `LICENSE` (Apache 2.0), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- **Connection Pooling (IMP-005)**: `httpc:set_keepalive(60000, 100)` in `handler.lua` eliminates TCP socket churn.
- **Fast-Path Lua Pre-Filter (IMP-007)**: `quick_pii_check()` bypasses sidecar network hops for prompts with no potential PII signals.
- **Strict JSON Validation (IMP-006)**: Malformed JSON on `application/json` routes rejected with RFC 7807 400 Bad Request.
- **ADR 0001** and **ADR 0002**: Architecture Decision Records for BCB compliance controls and OTel GenAI privacy scrubbing.

### Fixed
- Missing `import os` in `test_kong_proxy.py` (IMP-001).
- Missing `Optional` typing import in `pii_engine.py` (IMP-002).
- GitHub Actions CI workflow: added `--profile oss`, TLS healthcheck probes, containerized admin health check (IMP-003).

---

## [1.0.0] — 2026-09-16

### Added
- Initial repository: Kong AI Gateway reference architecture for BCB CMN 4.893/2021 compliance.
- Custom Kong Lua plugins: `bcb-pii-sanitizer` and `bcb-otel-scrubber`.
- Python FastAPI PII sanitizer microservice with Brazilian CPF, CNPJ, phone, email, bank account, money, and name detection.
- Docker Compose deployment configuration.
- k6 performance benchmark suite.
