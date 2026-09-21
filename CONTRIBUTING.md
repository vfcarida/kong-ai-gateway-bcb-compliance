# Contributing to Kong AI Gateway — BCB Regulatory Controls

Thank you for your interest in contributing to the **Kong AI Gateway — BCB Regulatory Controls** project. This reference architecture provides technical control building blocks for financial institutions adopting Generative AI under Brazilian regulatory frameworks.

We welcome pull requests, bug reports, documentation updates, and architectural discussions.

---

## 📋 Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

---

## 🛠️ Development Environment Setup

### Prerequisites
- **Git**
- **Docker & Docker Compose** (v24.0+)
- **Python 3.11+** (Python 3.12 recommended)
- **Kong Pongo** (Optional, for running Lua Busted plugin specs locally)

### 1. Fork and Clone
```bash
git clone https://github.com/vfcarida/kong-ai-gateway-bcb-compliance.git
cd kong-ai-gateway-bcb-compliance
```

### 2. Python Virtual Environment Setup
```bash
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r pii-sanitizer/requirements.txt
pip install pytest pytest-asyncio httpx flake8 mypy requests
```

### 3. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

---

### 4. Developer Tools & Pre-commit Hooks (Optional)
Install pre-commit hooks to automatically format and lint files before commit:
```bash
pip install pre-commit
pre-commit install
```
A standard `Makefile` is also available for Linux/macOS and WSL environments:
```bash
make help       # List available development targets
make test       # Run pytest test suite
make up-oss     # Start the Open Source docker stack
make lint       # Run linting checks
```

---

## 🧪 Testing Guidelines

Before opening a pull request, ensure all test suites pass locally.

### 1. Python Pytest Suite
Runs the 42+ unit and integration tests covering PII detection, checksum verification, synthetic consistency, and hardening:
```bash
pytest pii-sanitizer/tests/ -v
```

### 2. End-to-End Integration Verification
Boot the open-source profile and execute the verification test:
```bash
docker compose --profile oss up -d --build
python test_kong_proxy.py
docker compose --profile oss down -v
```

### 3. Lua Plugin Specs (Kong Pongo)
If you have [Kong Pongo](https://github.com/Kong/kong-pongo) installed:
```bash
pongo run spec/
```

---

## 📐 Coding Standards & Conventions

### Python Code Style
- Format using PEP 8 standards with a maximum line length of 120 characters.
- Use explicit type annotations on public functions and schemas.
- Ensure `flake8 pii-sanitizer/app --max-line-length=120` reports zero errors.

### Lua PDK Style
- Follow standard OpenResty / Kong PDK guidelines.
- Use non-blocking cosockets (`resty.http`) and place long-lived sockets into the keepalive pool via `httpc:set_keepalive(60000, 100)`.
- Never execute blocking I/O or network cosockets in the `body_filter_by_lua` phase.

### Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat: add CPF checksum validation in Lua fast-path`
- `fix: resolve missing os import in test_kong_proxy`
- `docs: update CMN 4.893 regulatory citations`
- `test: add Busted test for malformed JSON rejection`

---

## 🚀 Pull Request Process

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Commit Your Changes**: Keep commits atomic and focused.
3. **Run Validation Checks**: Confirm `pytest` and `docker compose` configs pass.
4. **Submit PR**: Target the `main` branch with a clear description of the problem solved, evidence of test runs, and any regulatory references.

---

## 🔒 Reporting Security Vulnerabilities

Please do not report security vulnerabilities through public GitHub issues. Follow the procedure outlined in our [Security Policy](SECURITY.md).
