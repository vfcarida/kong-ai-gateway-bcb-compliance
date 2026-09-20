# ADR 0002: OpenTelemetry GenAI Privacy Scrubbing & Telemetry Preservation

## Status
Accepted (Amended for Real OpenTelemetry Pipeline & Defensible Regulatory Alignment)

## Context
Monitoring Generative AI workloads requires observing operational metrics such as token consumption (`input_tokens`, `output_tokens`), request latencies, error rates, model performance, and cloud chargebacks. Standard OpenTelemetry (OTel) GenAI semantic conventions (v1.37+) recommend exporting attributes such as `gen_ai.prompt` and `gen_ai.completion` alongside system metrics.

However, exporting raw prompt and completion payloads in OpenTelemetry traces introduces significant security and privacy risks:
- **Regulatory Risk**: Storing unencrypted customer text inside third-party APM tools (e.g., Datadog, Jaeger, Grafana Tempo) introduces confidentiality risks under Brazilian Central Bank regulations (Resolução CMN nº 4.893/2021, as amended by CMN nº 5.274/2025, and Resolução BCB nº 85/2021).
- **The AI Visibility Paradox**: Organizations are caught between needing visibility into LLM operational metrics/costs and preventing sensitive customer data from being exported to external telemetry backends.

## Decision
We implement a **dual-layer defense-in-depth telemetry privacy pipeline** combining Kong Gateway and an OpenTelemetry Collector:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ KONG AI GATEWAY (3.14 OSS & Enterprise)                                    │
│                                                                            │
│  [HTTP Request] ──► [bcb-pii-sanitizer] ──► [ai-proxy]                     │
│                            │                      │                        │
│                            ▼                      ▼                        │
│               [bcb-otel-scrubber]          [opentelemetry]                 │
│              (Log Serialization)         (Bundled OTLP Traces)             │
│                      │                            │                        │
│                      ▼ (kong.log)                 ▼ (OTLP HTTP /v1/traces) │
│              [file-log / Audit]                   │                        │
└───────────────────────────────────────────────────┼────────────────────────┘
                                                    │
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ OPENTELEMETRY COLLECTOR (Contrib Pipeline)                                 │
│                                                                            │
│  [OTLP Receiver: 4317 gRPC / 4318 HTTP]                                    │
│                          │                                                 │
│                          ▼                                                 │
│  [Processor: attributes/redact_genai]                                      │
│    • gen_ai.prompt     ──► [REDACTED_BY_BCB_COMPLIANCE_POLICY]             │
│    • gen_ai.completion ──► [REDACTED_BY_BCB_COMPLIANCE_POLICY]             │
│    • gen_ai.usage.*    ──► PRESERVED (input_tokens, output_tokens)         │
│    • gen_ai.system     ──► PRESERVED (provider, model name)                │
│                          │                                                 │
│                          ▼                                                 │
│  [Exporter: debug / external APM backends (Jaeger, Tempo, Datadog)]        │
└────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Rules:

1. **Native OTLP Span Export**:
   - Kong Gateway utilizes the bundled `opentelemetry` plugin (available in both OSS and Enterprise editions) to emit W3C-correlated distributed tracing spans to `http://otel-collector:4318/v1/traces`.

2. **Collector-Side Attribute Redaction (`attributes/redact_genai`)**:
   - The OpenTelemetry Collector executes the `attributes/redact_genai` processor on the `traces` pipeline.
   - Programmatically redacts sensitive payload attributes:
     - `gen_ai.prompt` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`
     - `gen_ai.completion` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`
     - `ai.prompt` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`
     - `ai.completion` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`

3. **Gateway Log Serialization Scrubbing (`bcb-otel-scrubber`)**:
   - In Kong's Lua execution context, `bcb-otel-scrubber` operates during the `log` phase.
   - Sets `kong.log.set_serialize_value` to redact prompt and completion text before audit logs are written to disk or forwarded via `file-log`, `tcp-log`, or `http-log`.

4. **Strict Metric Preservation**:
   - Operational and financial metadata attributes are strictly preserved without redaction across both traces and metrics:
     - `gen_ai.system` (e.g., `openai`, `aws_bedrock`)
     - `gen_ai.request.model` (e.g., `gpt-4o`, `titan-express`)
     - `gen_ai.operation.name` (e.g., `chat`)
     - `gen_ai.usage.input_tokens` (Integer)
     - `gen_ai.usage.output_tokens` (Integer)
     - `http.response.status_code` (Integer)
     - `kong.latency` & `upstream.latency` (Milliseconds)

5. **Modern Exporter Configuration**:
   - Replaced deprecated `logging` exporter with `debug` (`verbosity: detailed`) in `config/otel-collector-config.yml`.

## Consequences
- **Positive**: Addresses the "AI Visibility Paradox" by technical separation of concerns. Operational telemetry for FinOps attribution and performance monitoring is preserved, while prompt and completion text attributes are scrubbed before reaching external APM networks.
- **Positive**: Architecture eliminates unbacked claims: Kong native spans flow through an actual redaction processor in the OTel Collector, while the Lua plugin protects log serialization.
- **Trade-off**: APM trace views will not display raw text conversations (which must instead be retrieved, if necessary and legally authorized, from internal access-controlled audit sinks).
- **Scope Qualification**: This pipeline provides technical safeguards against accidental transmission of prompt text into APM traces and local logs; it does not replace institutional data classification and governance policies required by BCB regulations.
