# PII Sanitizer API Specification (OpenAPI 3.1)

This specification defines the HTTP REST interface exposed by the **PII Sanitizer & Mock LLM Controller** microservice (`pii-sanitizer`), running locally on port `8443` (TLS) and mapped to host port `8088`.

---

## 🌐 Base URL & Protocol
- **Base URL**: `https://pii-sanitizer:8443` (Internal Docker network) / `https://localhost:8088` (Host access)
- **Transport Security**: TLS 1.2+ mandatory. Unencrypted HTTP requests are rejected at the transport layer.
- **Content Type**: `application/json` (Requests) / `application/json` or `application/problem+json` (Responses)

---

## 📑 Endpoints Summary

| Method | Path | Description | Production Available |
|---|---|---|:---:|
| `GET` | `/health` | Container readiness and operational health probe. | Yes |
| `GET` | `/metrics` | Prometheus text-format operational and DLP telemetry metrics. | Yes |
| `POST` | `/sanitize` | Real-time Brazilian PII detection and redaction engine. | Yes |
| `POST` | `/sanitize-batch` | High-throughput batch sanitization for RAG & vector ingestion. | Yes |
| `POST` | `/re-identify` | Restores original PII entities from replacement tokens via session vault. | Yes |
| `GET` | `/` | Service metadata and version discovery. | Yes |
| `POST` | `/mock-llm/v1/chat/completions` | OpenAI-compatible mock LLM chat completion endpoint. | Dev Only (`ENABLE_MOCK_LLM=true`) |
| `GET` | `/mock-llm/last-request` | Memory inspection probe to verify upstream payload safety. | Dev Only (`ENABLE_MOCK_LLM=true`) |
| `POST` | `/mock-llm/reset` | Resets in-memory mock request state and session cache. | Dev Only (`ENABLE_MOCK_LLM=true`) |

---

## 1. `GET /health`

### Description
Performs operational health verification for Kubernetes liveness/readiness probes.

### Response (200 OK)
```json
{
  "status": "healthy",
  "service": "pii-sanitizer",
  "version": "2.0.0",
  "compliance": "BCB CMN 4893/21 & BCB 85/21",
  "tls_enabled": true
}
```

---

## 2. `GET /metrics`

### Description
Exposes operational metrics in the standard Prometheus / OpenMetrics text exposition format for Kubernetes ServiceMonitor and APM scraping.

### Response (200 OK)
```text
Content-Type: text/plain; version=0.0.4; charset=utf-8

# HELP pii_sanitizer_requests_total Total HTTP requests handled by the PII sanitizer
# TYPE pii_sanitizer_requests_total counter
pii_sanitizer_requests_total{endpoint="/sanitize",status="200"} 42
# HELP pii_sanitizer_entities_detected_total Total PII entities intercepted and redacted
# TYPE pii_sanitizer_entities_detected_total counter
pii_sanitizer_entities_detected_total{type="CPF"} 18
pii_sanitizer_entities_detected_total{type="CREDIT_CARD"} 6
# HELP pii_vault_active_sessions Number of currently active sessions in the token vault
# TYPE pii_vault_active_sessions gauge
pii_vault_active_sessions 3
```

---

## 3. `POST /sanitize`

### Description
Scans input text, detects Brazilian financial and personal PII data (CPF, CNPJ, Payment Cards/PAN, BCB PIX Random Keys/EVP under Res. 1/2020, Brazilian RG, Bank Accounts, Phone Numbers, Emails, Full Names, Money), and applies placeholder redaction or deterministic synthetic substitution. All CPF, CNPJ, and Payment Cards are mathematically verified using Modulo-11 and ISO/IEC 7812 Luhn checksums.

### Request Body (`SanitizeRequest`)
```json
{
  "text": "Transferir R$ 2.500,00 para o CPF 123.456.789-09 do cliente Carlos Silva, conta 56789-0 agência 1234.",
  "redact_type": "placeholder",
  "session_id": "session-financial-tx-9941"
}
```

#### Fields:
- `text` (*string, required*): The raw prompt or message content to inspect. Max 1,000,000 characters.
- `redact_type` (*string, optional, default: `"placeholder"`*):
  - `"placeholder"`: Replaces entities with indexed tags (e.g., `[REDACTED_CPF_1]`, `[REDACTED_PIX_KEY_1]`).
  - `"synthetic"`: Replaces entities with mathematically valid, context-preserving synthetic fake values.
- `session_id` (*string, optional*): When provided with `redact_type="synthetic"`, ensures that identical entities across sequential API calls receive the exact same synthetic replacement value.

---

## 4. `POST /sanitize-batch`

### Description
High-throughput batch sanitization API designed for enterprise RAG (Retrieval Augmented Generation) chunk ingestion and bulk document pre-filtering. Maintains deterministic synthetic pseudonym consistency across all items in the batch or within the referenced session vault.

### Request Body (`SanitizeBatchRequest`)
```json
{
  "items": [
    { "id": "chunk-01", "text": "Cliente João Silva com CPF 123.456.789-09 e PIX evp: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d" },
    { "id": "chunk-02", "text": "Segunda menção ao titular CPF 123.456.789-09 para confirmação de conta." }
  ],
  "redact_type": "synthetic",
  "session_id": "rag-ingestion-batch-101"
}
```

#### Fields:
- `items` (*array of objects, required*): List of text chunks to sanitize (max 100 items per batch).
  - `id` (*string, optional*): Client correlation ID for tracking chunks.
  - `text` (*string, required*): Text content to inspect and sanitize (max 1,000,000 characters per item).
- `redact_type` (*string, optional, default: `"placeholder"`*): `"placeholder"` or `"synthetic"`.
- `session_id` (*string, optional*): Session vault identifier for multi-chunk synthetic consistency and egress re-identification.

### Response (200 OK - `SanitizeBatchResponse`)
```json
{
  "items": [
    {
      "id": "chunk-01",
      "sanitized_text": "Cliente Mariana Santos com CPF 492.381.047-52 e PIX evp: 987fcba9-1234-4567-89ab-cdef01234567",
      "pii_detected": [ ... ],
      "total_entities": 3
    },
    {
      "id": "chunk-02",
      "sanitized_text": "Segunda menção ao titular CPF 492.381.047-52 para confirmação de conta.",
      "pii_detected": [ ... ],
      "total_entities": 1
    }
  ],
  "total_items": 2,
  "total_entities": 4,
  "processing_time_ms": 2.15,
  "redact_type": "synthetic"
}
```

---

## 5. `POST /re-identify`

### Description
Restores authentic sensitive PII entities from replacement placeholder tokens (e.g. `[REDACTED_CPF_1]`) or synthetic fake values using the session's tokenization vault. Enables authorized egress re-identification for internal banking workflows. Aliased to `POST /de-anonymize`.

### Request Body (`ReidentifyRequest`)
```json
{
  "text": "Atendimento concluído para o titular do CPF [REDACTED_CPF_1] referente a transação de [REDACTED_MONEY_1].",
  "session_id": "session-financial-tx-9941"
}
```

#### Fields:
- `text` (*string, required*): The sanitized text containing tokens or synthetic values to restore. Cannot be empty or whitespace-only.
- `session_id` (*string, required*): The session ID holding the token vault mappings established during a preceding `/sanitize` call.

### Response (200 OK - `ReidentifyResponse`)
```json
{
  "reidentified_text": "Atendimento concluído para o titular do CPF 123.456.789-09 referente a transação de R$ 2.500,00.",
  "restored_entities": 2,
  "session_id": "session-financial-tx-9941",
  "processing_time_ms": 0.35
}
```

---

## 4. RFC 7807 Problem Details Error Responses

When an error occurs, the API returns `application/problem+json`:

### Example: 400 Bad Request (Empty Text)
```json
{
  "type": "https://tools.ietf.org/html/rfc7807#section-3.1",
  "title": "Bad Request",
  "status": 400,
  "detail": "The input 'text' field cannot be empty.",
  "instance": "/sanitize"
}
```

### Example: 404 Not Found (Disabled Mock Endpoint)
```json
{
  "type": "https://tools.ietf.org/html/rfc7807#section-3.1",
  "title": "Not Found",
  "status": 404,
  "detail": "Mock LLM endpoints are disabled in this environment (ENABLE_MOCK_LLM=false).",
  "instance": "/mock-llm/v1/chat/completions"
}
```

### Example: 413 Payload Too Large (DoS / ReDoS Guard)
```json
{
  "type": "https://tools.ietf.org/html/rfc7807#section-3.1",
  "title": "Payload Too Large",
  "status": 413,
  "detail": "The input 'text' exceeds the maximum allowed length of 1000000 characters.",
  "instance": "/sanitize"
}
```

---

## 7. Compliance HTTP Correlation Headers

When requests transit through Kong Gateway configured with `bcb-pii-sanitizer`:

| Header | Direction | Description | Example |
|---|---|---|---|
| `X-Session-ID` / `x-session-id` | Ingress (Client -> Kong) | Client-provided session identifier for persistent pseudonymization and Reversible Token Vault. | `session-usr-4421` |
| `X-BCB-PII-Sanitized` | Upstream (Kong -> LLM) | Injected by Kong indicating request was inspected and scrubbed. | `true` |
| `X-BCB-PII-Entities-Count` | Upstream (Kong -> LLM) | Total count of PII entities redacted in the prompt. | `3` |
| `X-BCB-Session-ID` | Upstream (Kong -> LLM) | Propagated session identifier for upstream telemetry and correlation. | `session-usr-4421` |
| `X-BCB-Compliance-Verified` | Egress (Kong -> Client) | Confirmation that the prompt satisfied Resolução CMN 4893/21 & BCB 85/21. | `true` |
| `X-BCB-PII-Entities-Redacted` | Egress (Kong -> Client) | Number of sensitive entities masked before upstream LLM ingestion. | `3` |

---

## 8. `POST /mock-llm/v1/chat/completions`

### Description
Mock OpenAI-compatible chat completion upstream. Calculates prompt and completion token counts to test OWASP LLM10:2025 rate-limiting controls. Guarded by `ENABLE_MOCK_LLM`.

### Request Body
```json
{
  "model": "gpt-4o",
  "messages": [
    {
      "role": "user",
      "content": "Safe prompt"
    }
  ]
}
```

### Response (200 OK)
```json
{
  "id": "chatcmpl-mock-bcb-4893-21",
  "object": "chat.completion",
  "created": 1727289600,
  "model": "mock-compliance-llm",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Compliance verification: Safe response generated by Mock LLM under BCB CMN 4893/21."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 35,
    "total_tokens": 60
  }
}
```
