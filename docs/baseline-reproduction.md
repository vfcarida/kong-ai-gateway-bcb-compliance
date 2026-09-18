# KAG-T01: Preflight & Baseline Reproduction Report

**Task ID**: KAG-T01  
**Repository**: [kong-ai-gateway-bcb-compliance](https://github.com/vfcarida/kong-ai-gateway-bcb-compliance)  
**Baseline Git SHA**: `44d16bee8eb983ff1b8ad5b1e5ab9e93eae2185c` (branch `main`)  
**Status**: Completed — Baseline Reproduced  

---

## 1. Preflight Verification

### Git State
- **HEAD Commit SHA**: `44d16bee8eb983ff1b8ad5b1e5ab9e93eae2185c` (verified via `git rev-parse HEAD`)
- **Working Tree**: Clean prior to baseline probe/documentation addition (`git status`).

### Runtime & Dependency Versions
- **Python Runtime**: `Python 3.12.10`
- **Pytest**: `pytest 9.1.1`
- **Installed Packages (`pip freeze`)**:
  ```text
  annotated-doc==0.0.5
  annotated-types==0.8.0
  anyio==4.15.1
  certifi==2026.7.22
  charset-normalizer==3.5.1
  click==8.5.0
  colorama==0.4.6
  fastapi==0.141.1
  h11==0.16.0
  httpcore==1.0.9
  httptools==0.8.0
  httpx==0.28.1
  idna==3.20
  iniconfig==2.3.0
  packaging==26.3
  pluggy==1.6.0
  pydantic==2.13.5
  pydantic_core==2.46.5
  Pygments==2.21.0
  pytest==9.1.1
  python-dotenv==1.2.3
  PyYAML==6.0.3
  requests==2.34.2
  starlette==1.6.0
  typing-inspection==0.4.4
  typing_extensions==4.16.0
  urllib3==2.8.0
  uvicorn==0.53.0
  watchfiles==1.2.0
  websockets==17.1
  ```

---

## 2. Test Suite Baseline Execution

Executed command:
```bash
pytest pii-sanitizer/tests/ -v
```

### Pytest Execution Log
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0 -- .venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\vinicius\Documents
configfile: pyproject.toml
plugins: anyio-4.15.1
collecting ... collected 7 items

pii-sanitizer\tests\test_sanitizer.py::test_health_endpoint PASSED       [ 14%]
pii-sanitizer\tests\test_sanitizer.py::test_validate_cpf_checksums PASSED [ 28%]
pii-sanitizer\tests\test_sanitizer.py::test_validate_cnpj_checksums PASSED [ 42%]
pii-sanitizer\tests\test_sanitizer.py::test_sanitize_placeholder PASSED  [ 57%]
pii-sanitizer\tests\test_sanitizer.py::test_sanitize_synthetic PASSED    [ 71%]
pii-sanitizer\tests\test_sanitizer.py::test_rfc7807_empty_text PASSED    [ 85%]
pii-sanitizer\tests\test_sanitizer.py::test_mock_llm_completion PASSED   [100%]

======================== 7 passed, 2 warnings in 0.83s ========================
```

Result: **7 passed, 0 failed (exit code 0)**.

---

## 3. PII Engine Defect Evidence ("Before" State)

A probe script was created at `scripts/engine_probe.py` to evaluate `detect_and_sanitize()` against the fixed test cases without modifying engine logic.

Execution command:
```bash
python scripts/engine_probe.py
```

### Captured Probe Output
```text
================================================================================
KAG-T01: PII Engine Baseline Probe (Before Fixes)
================================================================================

--- Case 1: Order Number (11 digits) ---
Input: Pedido 12345678901 faturado com sucesso
Known Defect Context: [F-01] Raw 11-digit regex matches without checksum; falsely detected as CPF.
Sanitized Text: Pedido [REDACTED_CPF_1] faturado com sucesso
Total Entities Detected: 1
  - Type: CPF | Original: '12345678901' | Replacement: '[REDACTED_CPF_1]' | Span: [7:18]

--- Case 2: Phone Numbers (formatted and unformatted 11-digit) ---
Input: Ligue para (11) 98765-4321 ou envie mensagem para 11987654321
Known Defect Context: [F-01] Unformatted 11-digit phone is captured as CPF before or instead of PHONE.
Sanitized Text: Ligue para [REDACTED_PHONE_1] ou envie mensagem para [REDACTED_CPF_1]
Total Entities Detected: 2
  - Type: PHONE | Original: '(11) 98765-4321' | Replacement: '[REDACTED_PHONE_1]' | Span: [11:26]
  - Type: CPF | Original: '11987654321' | Replacement: '[REDACTED_CPF_1]' | Span: [50:61]

--- Case 3: Invalid CPF (failing checksum validation) ---
Input: CPFs invalidos: 123.456.789-00 e 111.111.111-11 e raw 12345678900
Known Defect Context: [F-01] All invalid CPFs detected as CPF because validate_cpf_digits is never called.
Sanitized Text: CPFs invalidos: [REDACTED_CPF_3] e [REDACTED_CPF_2] e raw [REDACTED_CPF_1]
Total Entities Detected: 3
  - Type: CPF | Original: '123.456.789-00' | Replacement: '[REDACTED_CPF_3]' | Span: [16:30]
  - Type: CPF | Original: '111.111.111-11' | Replacement: '[REDACTED_CPF_2]' | Span: [33:47]
  - Type: CPF | Original: '12345678900' | Replacement: '[REDACTED_CPF_1]' | Span: [54:65]

--- Case 4: Bank Account (standard Brazilian format) ---
Input: Favor transferir para Agência 1234 Conta 56789-0
Known Defect Context: [F-03] Bank account regex fails to capture Agência + Conta compound pattern (0 entities).
Sanitized Text: Favor transferir para Agência 1234 Conta 56789-0
Total Entities Detected: 0
  - (None detected)

================================================================================
Probe Complete — Baseline State Successfully Captured.
================================================================================
```

### Analysis of Defects

1. **Defect F-01 — Checksum Validators Disconnected & 11-Digit Collision**:
   - `validate_cpf_digits()` and `validate_cnpj_digits()` exist in `pii_engine.py` (lines 18, 35) and pass unit tests, but are **never invoked** within `detect_and_sanitize()` (lines 157-220).
   - Any 11-digit string matching `\b\d{11}\b` is classified as `CPF`, causing false positives on order numbers (`Pedido 12345678901`) and unformatted Brazilian phone numbers (`11987654321`).
   - Mathematically invalid CPFs (`123.456.789-00`, `111.111.111-11`, `12345678900`) are flagged as valid CPF entities without verification.

2. **Defect F-03 — Bank Account Compound Format False Negative**:
   - Regex `(?i)\b(?:ag(?:ência)?|conta|c/c)\s*:?\s*\d{3,5}[-\s]?\d{3,7}[-\s]?[0-9kK]?\b` assumes a single prefix followed by two digit blocks.
   - For realistic financial strings like `"Agência 1234 Conta 56789-0"`, the parser fails to match both `"Agência 1234"` (stopped by `"Conta"`) and `"Conta 56789-0"` (fails the `\d{3,7}` second block requirement), resulting in **0 entities detected**.

---

## 4. Kong Gateway OSS vs. Enterprise Boot Reality

### Docker Compose Configuration Validation
- Executed: `docker compose config`
- Exit Code: `0` (valid syntax). Services declared: `kong-gateway`, `pii-sanitizer`, `redis-vector`, `otel-collector`.

### Gateway Boot Check: **NOT RUN**
- **Status**: `NOT RUN`
- **Reason**: Docker engine / daemon is not running on the host system:
  ```text
  failed to connect to the docker API at npipe:////./pipe/docker_engine; 
  check if the path is correct and if the daemon is running: open //./pipe/docker_engine: The system cannot find the file specified.
  ```

### Static Architecture Analysis of Kong Plugins
- **Enterprise Plugins in DB-less Configuration** (`config/kong.yaml`):
  - `ai-semantic-cache` (lines 67-80): Vector caching backed by Redis.
  - `ai-rate-limiting-advanced` (lines 82-93): Token-based window rate limiting.
- **Licensing Constraint**:
  - Image configured: `kong/kong-gateway:3.14` (`docker-compose.yml:64`).
  - License environment variable: `KONG_LICENSE_DATA: "${KONG_LICENSE_DATA:-}"` (`docker-compose.yml:72`) defaults to empty.
  - In Kong Gateway Enterprise DB-less mode, running unlicensed Enterprise plugins causes the declarative configuration parser to reject the configuration or disable proprietary plugins at startup.

---

## 5. Scope & Invariants Compliance

- **No logic changed**: All existing code in `pii-sanitizer/app/pii_engine.py`, `config/kong.yaml`, and `docker-compose.yml` remains unmodified.
- **New files only**:
  - `scripts/engine_probe.py`
  - `docs/baseline-reproduction.md`
- **Next Task**: `KAG-T02`.
