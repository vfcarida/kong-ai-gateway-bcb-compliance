# ADR 0001: Brazilian Central Bank (BCB CMN 4893/21 & BCB 85/21) Compliance Architecture

## Status
Accepted

## Context
Financial institutions operating under the jurisdiction of the Brazilian Central Bank (Banco Central do Brasil - BCB) are subject to stringent regulatory frameworks governing cloud computing, data processing, incident response, and cybersecurity. Specifically:
- **Resolução CMN nº 4.893/21**: Establishes mandatory requirements for cybersecurity policies, cloud contracting, data residency, operational continuity, and incident tracking.
- **Resolução BCB nº 85/21**: Mandates specific protocols for data classification, governance, and incident reporting to regulatory bodies.

Integrating Large Language Models (LLMs) into core financial services introduces novel risks:
1. **Data Loss Prevention (Confidentiality)**: Inadvertent transmission of Personally Identifiable Information (PII) such as Brazilian CPFs, CNPJs, bank account numbers, and transaction details to external cloud LLM providers.
2. **Provider Dependability & Continuity (Availability)**: Outages or high latency from cloud AI providers violate BCB requirements for continuous service delivery.
3. **Data Residency & Geo-fencing**: Compliance with BCB Art. 16 requires explicit risk management regarding cloud data centers located outside Brazilian jurisdiction.
4. **Audit Trail & Correlation (Integrity)**: End-to-end traceability of AI inference requests with non-repudiable transaction IDs.

## Decision
We deploy the **Kong AI Gateway** as an enterprise-grade AI Control Plane and Data Plane in front of all LLM workloads. The architecture guarantees compliance through the following technical mechanisms:

### 1. Dual-Layer PII Interception & Obfuscation
- Pre-request payload inspection using a custom non-blocking Lua plugin (`bcb-pii-sanitizer`) combined with a high-performance Python microservice (`pii-sanitizer`).
- Automated detection and redaction of CPFs (checksum-validated), CNPJs, phone numbers, emails, names, bank accounts, and monetary amounts before payloads cross network boundaries.
- Support for both `placeholder` (`[REDACTED_CPF_1]`) and `synthetic` mode (generating mathematically valid synthetic credentials to maintain LLM semantic context).

### 2. Multi-Provider LLM Abstraction & Automatic Failover
- Use Kong `ai-proxy` and failover routing rules to implement provider redundancy:
  - **Primary**: OpenAI / Azure OpenAI (High performance)
  - **Secondary**: AWS Bedrock (Regional cloud redundancy)
  - **Tertiary**: Localized Llama 3 via Ollama (On-premises / air-gapped fallback)
- Guarantees the **Availability** pillar under BCB CMN 4893/21.

### 3. FinOps & OWASP LLM Mitigation
- **Semantic Caching (`ai-semantic-cache`)**: Powered by a Redis Vector Search backend (cosine similarity > 0.85) to eliminate duplicate upstream LLM calls, reducing API expenses and cutting response times to sub-milliseconds.
- **Token-Based Rate Limiting (`ai-rate-limiting-advanced`)**: Enforces consumption budgets calculated on LLM token counts (`gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens`), mitigating OWASP LLM10:2025 (Denial of Wallet).
- **Prompt Guardrails (`ai-prompt-guard`)**: Intercepts direct/indirect prompt injection attempts (OWASP LLM01:2025).

### 4. OpenTelemetry & Auditability
- Trace correlation via `correlation-id` injecting standard `X-Request-ID` headers.
- OpenTelemetry GenAI v1.37+ instrumentation with payload scrubbing (`bcb-otel-scrubber`) to record operational telemetry without exposing sensitive prompt text in network traces.
- Immutable audit log outputs serialized to structured JSON files (`/tmp/audit-logs/kong-audit.log`).

## Consequences
- **Positive**: Complete compliance with BCB CMN 4893/21 and BCB 85/21; sub-millisecond cache latency for common queries; total decoupling from specific cloud AI vendors; bulletproof audit trails.
- **Negative**: Sub-5ms latency overhead introduced by pre-function PII scanning (mitigated via `lua_shared_dict` caching).
