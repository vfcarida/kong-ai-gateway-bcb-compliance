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
| `POST` | `/sanitize` | Real-time Brazilian PII detection and redaction engine. | Yes |
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

## 2. `POST /sanitize`

### Description
Scans input text, detects Brazilian financial and personal PII data (CPF, CNPJ, Bank Accounts, Phone Numbers, Emails, Full Names, Money), and applies placeholder redaction or deterministic synthetic substitution.

### Request Body (`SanitizeRequest`)
```json
{
  "text": "Transferir R$ 2.500,00 para o CPF 123.456.789-09 do cliente Carlos Silva, conta 56789-0 agência 1234.",
  "redact_type": "placeholder",
  "session_id": "session-financial-tx-9941"
}
```

#### Fields:
- `text` (*string, required*): The raw prompt or message content to inspect. Cannot be empty or whitespace-only.
- `redact_type` (*string, optional, default: `"placeholder"`*):
  - `"placeholder"`: Replaces entities with indexed tags (e.g., `[REDACTED_CPF_1]`, `[REDACTED_MONEY_1]`).
  - `"synthetic"`: Replaces entities with mathematically valid, context-preserving synthetic fake values.
- `session_id` (*string, optional*): When provided with `redact_type="synthetic"`, ensures that identical entities across sequential API calls receive the exact same synthetic replacement value.

### Response (200 OK - `SanitizeResponse`)
```json
{
  "sanitized_text": "Transferir [REDACTED_MONEY_1] para o CPF [REDACTED_CPF_1] do cliente [REDACTED_NAME_1], conta [REDACTED_BANK_ACCOUNT_1].",
  "pii_detected": [
    {
      "type": "MONEY",
      "original": "R$ 2.500,00",
      "replacement": "[REDACTED_MONEY_1]",
      "start": 11,
      "end": 22,
      "checksum_valid": null
    },
    {
      "type": "CPF",
      "original": "123.456.789-09",
      "replacement": "[REDACTED_CPF_1]",
      "start": 34,
      "end": 48,
      "checksum_valid": true
    },
    {
      "type": "NAME",
      "original": "Carlos Silva",
      "replacement": "[REDACTED_NAME_1]",
      "start": 60,
      "end": 72,
      "checksum_valid": null
    },
    {
      "type": "BANK_ACCOUNT",
      "original": "conta 56789-0 agência 1234",
      "replacement": "[REDACTED_BANK_ACCOUNT_1]",
      "start": 74,
      "end": 101,
      "checksum_valid": null
    }
  ],
  "total_entities": 4,
  "processing_time_ms": 1.45,
  "redact_type": "placeholder"
}
```

---

## 3. RFC 7807 Problem Details Error Responses

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

---

## 4. `POST /mock-llm/v1/chat/completions`

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
