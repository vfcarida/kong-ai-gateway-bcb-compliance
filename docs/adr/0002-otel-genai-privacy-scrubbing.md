# ADR 0002: OpenTelemetry GenAI Privacy Scrubbing & Telemetry Preservation

## Status
Accepted

## Context
Monitoring Generative AI workloads requires observing operational metrics such as token consumption (`input_tokens`, `output_tokens`), request latencies, error rates, model performance, and cloud chargebacks. Standard OpenTelemetry (OTel) GenAI semantic conventions (v1.37+) recommend exporting attributes such as `gen_ai.prompt` and `gen_ai.completion` alongside system metrics.

However, exporting raw prompt and completion payloads in OpenTelemetry traces introduces a major security and compliance violation:
- **Regulatory Non-Compliance**: Storing unencrypted customer text inside APM tools (e.g., Datadog, Jaeger, Grafana Tempo) violates Brazilian Central Bank (BCB CMN 4893/21) confidentiality and data privacy directives.
- **The AI Visibility Paradox**: Organizations are trapped between needing visibility into LLM performance/costs and preventing sensitive customer data from being leaked to telemetry backends.

## Decision
We implement a custom Kong Gateway Lua plugin (`bcb-otel-scrubber`) that operates within the OpenTelemetry export pipeline.

### Architectural Rules:
1. **Attribute Scrubbing**: The plugin programmatically removes or redacts the values of sensitive attributes before spans leave the API Gateway:
   - `gen_ai.prompt` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`
   - `gen_ai.completion` → `[REDACTED_BY_BCB_COMPLIANCE_POLICY]`
2. **Metric Preservation**: Operational and financial metadata attributes are strictly preserved:
   - `gen_ai.system` (e.g., `openai`, `aws_bedrock`)
   - `gen_ai.request.model` (e.g., `gpt-4o`, `titan-express`)
   - `gen_ai.operation.name` (e.g., `chat`)
   - `gen_ai.usage.input_tokens` (Integer)
   - `gen_ai.usage.output_tokens` (Integer)
   - `http.response.status_code` (Integer)
   - `kong.latency` & `upstream.latency` (Milliseconds)
3. **Audit Correlation**: The span context is bound to `X-Request-ID` and the audit log serialization context (`ai.sanitizer.pii_identified`).

## Consequences
- **Positive**: Completely resolves the "AI Visibility Paradox". Telemetry metrics for FinOps chargeback and anomaly detection remain 100% accurate, while zero prompt text leaks into external APM networks.
- **Negative**: APM trace views will not display raw text conversations (which must instead be retrieved, if necessary and authorized, from internal encrypted compliance audit logs).
