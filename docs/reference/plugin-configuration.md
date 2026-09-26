# Kong Plugin Configuration Reference

This reference document describes the configuration schema, parameters, execution phases, and default values for the two custom Kong plugins provided in this repository:
1. **`bcb-pii-sanitizer`**: Real-time ingress PII detection, redaction, and prompt rewriting.
2. **`bcb-otel-scrubber`**: Log-phase privacy scrubbing and FinOps telemetry preservation.

---

## 1. `bcb-pii-sanitizer`

### Overview
- **Plugin Name**: `bcb-pii-sanitizer`
- **Execution Phase**: `access`
- **Plugin Priority**: `1010` (runs immediately prior to `ai-prompt-guard` at `1005` and `ai-proxy` at `1000`)
- **Primary Responsibility**: Intercepts OpenAI-compatible JSON chat completion payloads, validates mathematical check digits for Brazilian national identifiers, replaces sensitive entities with placeholders or synthetic values, and rewrites the downstream HTTP request body before routing to the upstream LLM.

### Configuration Schema

| Parameter | Type | Required | Default | Allowed Values | Description |
|---|---|:---:|---|---|---|
| `sanitizer_url` | `string` | **Yes** | `"https://pii-sanitizer:8443/sanitize"` | Valid HTTPS URL | The HTTPS endpoint of the PII Sanitizer microservice. |
| `ssl_verify` | `boolean` | No | `false` | `true`, `false` | Verifies the TLS certificate of the sanitizer microservice against trusted CAs. Set to `true` in production environments. |
| `timeout_ms` | `integer` | No | `1500` | `100` – `60000` | HTTP connect, send, and read timeout in milliseconds for sidecar calls. |
| `keepalive_timeout_ms`| `integer` | No | `60000` | `1000` – `3600000` | Max idle time in milliseconds before cosockets in the keepalive pool are closed. |
| `keepalive_pool_size` | `integer` | No | `100` | `1` – `10000` | Number of pooled cosocket connections maintained per Nginx worker. |
| `fail_open` | `boolean` | No | `false` | `true`, `false` | **Confidentiality Gate**: If `false` (default), gateway returns RFC 7807 `502 Bad Gateway` upon sanitizer failure. If `true`, request proceeds unredacted with a warning header. |
| `redact_type` | `string` | No | `"placeholder"` | `"placeholder"`, `"synthetic"` | Redaction strategy: `"placeholder"` replaces with `[REDACTED_CPF_1]`, `"synthetic"` replaces with deterministic fake entities. |

### In-Gateway Fast-Path Optimization (`quick_pii_check`)
To prevent unnecessary sidecar HTTP round-trips for non-sensitive prompts (e.g., standard code generation, translation queries), `handler.lua` executes an in-process pre-filter before invoking the external microservice:
- **Rule 1**: If the request body contains no ASCII digits (`0-9`), mathematical CPF, CNPJ, phone, money, and bank account detection is bypassed.
- **Rule 2**: If no digits and no uppercase Latin characters are present, name detection is bypassed.
- **Rule 3**: If neither condition is met, the prompt is deemed clean and forwarded directly upstream, reducing latency overhead to `<1ms`.

### Error Responses & RFC 7807 Format
When a request fails validation or the sanitizer service degrades, the plugin returns standard `application/problem+json`:
- **400 Bad Request**: Malformed or unparseable JSON on protected routes.
- **502 Bad Gateway**: Sanitizer connection timeout, unreachable service, or 5xx response when `fail_open: false`.

---

## 2. `bcb-otel-scrubber`

### Overview
- **Plugin Name**: `bcb-otel-scrubber`
- **Execution Phase**: `log`
- **Plugin Priority**: `90` (executes after proxy response completion during the asynchronous log serialization phase)
- **Primary Responsibility**: Inspects Kong's internal request serialization structure and sanitizes logged values via `kong.log.set_serialize_value`, ensuring that raw customer prompts are stripped from file logs while preserving operational FinOps metrics (`gen_ai.usage.*`).

### Configuration Schema

| Parameter | Type | Required | Default | Description |
|---|---|:---:|---|---|
| `log_redaction_marker` | `string` | No | `"[REDACTED_BY_BCB_SCRUBBER]"` | Replacement string inserted into logged prompt fields. |
| `scrub_request_body` | `boolean` | No | `true` | When true, strips raw request bodies from log entries. |
| `scrub_response_body` | `boolean` | No | `true` | When true, strips raw LLM completion bodies from log entries. |
| `preserve_finops_metrics`| `boolean` | No | `true` | Preserves token counters (`prompt_tokens`, `completion_tokens`, `total_tokens`), model names, and latencies. |

---

## 3. Declarative Configuration Example (`config/kong.yaml`)

```yaml
_format_version: "3.0"

services:
  - name: ai-llm-service
    url: https://pii-sanitizer:8443/mock-llm
    routes:
      - name: llm-proxy-route
        paths:
          - /llm-proxy
        strip_path: false
        methods:
          - POST
    plugins:
      - name: bcb-pii-sanitizer
        config:
          sanitizer_url: "https://pii-sanitizer:8443/sanitize"
          ssl_verify: false
          timeout_ms: 1500
          keepalive_timeout_ms: 60000
          keepalive_pool_size: 100
          fail_open: false
          redact_type: "placeholder"

      - name: bcb-otel-scrubber
        config:
          log_redaction_marker: "[REDACTED_BY_BCB_SCRUBBER]"
          scrub_request_body: true
          scrub_response_body: true
          preserve_finops_metrics: true
```
