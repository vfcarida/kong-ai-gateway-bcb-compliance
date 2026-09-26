# Getting Started Guide

This guide walks you through bootstrapping, configuring, and verifying the **Kong AI Gateway BCB Compliance** reference architecture on your local development workstation.

---

## 📋 Prerequisites

Before proceeding, ensure you have the following installed:
- **Docker Engine** (v24.0+) and **Docker Compose** (v2.20+)
- **Python** (v3.10+) with `pip` and virtual environment support
- **cURL** or an API testing client (e.g., Postman, HTTPie)
- **Make** (optional, recommended for developer shortcuts)

---

## 🚀 Step 1: Environment Configuration

1. Clone the repository and navigate to the project root:
   ```bash
   git clone https://github.com/vfcarida/kong-ai-gateway-bcb-compliance.git
   cd kong-ai-gateway-bcb-compliance
   ```

2. Copy the sample environment configuration file:
   ```bash
   cp .env.example .env
   ```

3. Review `.env` parameters:
   - For **Open-Source (OSS)** evaluation: Default values are completely self-contained. No external commercial licenses or API keys are required; traffic routes to the local TLS-hardened `pii-sanitizer` mock upstream.
   - For **Production / Cloud LLM** routing: Set `AI_PROVIDER=openai` (or `bedrock`) and fill in your corresponding provider API keys (`OPENAI_API_KEY` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).
   - For **Enterprise evaluation**: Provide a valid `KONG_LICENSE_DATA` string to enable Redis Vector caching and token rate limiting.

---

## 🛠️ Step 2: Ephemeral TLS Certificate Setup

The PII Sanitizer microservice terminates TLS locally on port `8443` (mapped to host port `8088`). Ephemeral development certificates can be verified or generated using the pure-Python generator:

```bash
# Verify existing development certificate:
python scripts/generate_dev_certs.py --verify
# Or via Makefile:
make certs-verify

# Regenerate fresh certificates on demand:
python scripts/generate_dev_certs.py
# Or via Makefile:
make certs
```

---

## 🐳 Step 3: Launching the Stack via Docker Compose

### Option A: Open-Source Profile (Recommended for Evaluation)
Runs 100% license-free Community Edition on `kong:3.14`:
```bash
docker compose --profile oss up -d --build
# Or via Makefile:
make up-oss
```
**Containers launched**:
- `kong-gateway-oss`: Kong Gateway DB-less core with custom Lua plugins.
- `pii-sanitizer`: Python FastAPI service terminating TLS on port 8443.
- `otel-collector`: OpenTelemetry Collector Contrib with span redaction pipeline.

### Option B: Enterprise Profile
Runs Kong Enterprise Edition (`kong/kong-gateway:3.14`) with Redis Vector semantic cache:
```bash
docker compose --profile enterprise up -d --build
# Or via Makefile:
make up-enterprise
```

---

## 🔍 Step 4: Health & Security Verification

### 1. Gateway Status
Kong's Admin API is bound strictly to container loopback (`127.0.0.1:8001`) to comply with Resolution CMN nº 4.893/2021. Check status via Docker exec:
```bash
docker exec -it kong-gateway-oss kong health
# Query internal loopback status endpoint:
docker exec -it kong-gateway-oss curl -s http://127.0.0.1:8001/status
```

### 2. PII Sanitizer TLS Verification
Verify HTTPS connectivity and rejection of unencrypted plaintext traffic:
```bash
# Verify TLS termination (returns 200 OK):
curl -k https://localhost:8088/health

# Verify plaintext rejection (confirms encryption in transit):
curl http://localhost:8088/health # (Should fail or reset connection)
```

---

## 🧪 Step 5: Execute End-to-End PII Sanitization

Send an OpenAI-compatible chat completion payload containing Brazilian financial PII to the gateway proxy ingress:

```bash
curl -i -X POST http://localhost:8000/llm-proxy \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {
        "role": "user",
        "content": "Por favor confirme a transferencia de R$ 1.500,00 para o cliente Carlos Silva, portador do CPF 123.456.789-09, conta corrente 56789-0 agência 1234."
      }
    ]
  }'
```

### Expected Flow:
1. **Kong Gateway** intercepts the request via the `bcb-pii-sanitizer` Lua plugin.
2. The payload is checked via the in-gateway pre-filter; detecting digits and keywords, it forwards the prompt to `https://pii-sanitizer:8443/sanitize`.
3. The PII Engine detects:
   - `MONEY`: `R$ 1.500,00`
   - `NAME`: `Carlos Silva`
   - `CPF`: `123.456.789-09` (checksum mathematically verified)
   - `BANK_ACCOUNT`: `agência 1234 conta corrente 56789-0`
4. The sanitized payload is forwarded upstream to the mock LLM.
5. Kong logs structured FinOps metrics while `bcb-otel-scrubber` scrubs logs and `otel-collector` scrubs tracing spans.

### Verify Upstream Redaction:
Check the mock LLM's last received payload to prove raw PII never reached the upstream model:
```bash
curl -k https://localhost:8088/mock-llm/last-request
```

### Verify Structured Audit Log:
Inspect the serialized log on the host:
```bash
tail -n 20 /tmp/audit-logs/kong-audit.log
```

---

## 🧪 Step 6: Running Automated Tests

Run the full Python test suite (112+ tests) covering checksum algorithms, adversarial fuzzing, TLS certificates, and mock guards:
```bash
pytest pii-sanitizer/tests/ -v
# Or via Makefile:
make test
```

Execute the end-to-end proxy verification script:
```bash
python test_kong_proxy.py
# Or via Makefile:
make test-e2e
```

---

## 🛑 Step 7: Teardown

Stop and remove all running containers and networks:
```bash
docker compose down
# Or via Makefile:
make down
```
