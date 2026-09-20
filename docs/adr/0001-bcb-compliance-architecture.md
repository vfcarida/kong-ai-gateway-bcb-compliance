# ADR 0001: Architecture Reference for Brazilian Central Bank (CMN 4.893/2021 & BCB 85/2021) Technical Controls

## Status
Accepted (Amended for Defensible Regulatory Alignment & Technical Precision)

## Context
Financial institutions and payment institutions operating under the regulatory umbrella of the Central Bank of Brazil (Banco Central do Brasil - BCB) and the National Monetary Council (Conselho Monetário Nacional - CMN) are subject to comprehensive frameworks governing cybersecurity and cloud computing:
- **Resolução CMN nº 4.893/2021** (published 2021-02-26, effective 2021-07-01; amended by **Resolução CMN nº 5.274/2025**): Establishes cybersecurity policies and mandatory requirements for contracting data processing, storage, and cloud computing services for financial institutions authorized by the BCB. Crucially, CMN 4.893/2021 does **not** mandate domestic data hosting; it permits cross-border cloud contracting provided institutions ensure regulatory access, auditability, business continuity, and prior communication to the regulator.
- **Resolução BCB nº 85/2021** (published 2021-04-08, effective 2021-07-01): Governs cybersecurity policy and requirements for contracting data processing and storage and cloud computing services specifically for **Payment Institutions** (*Instituições de Pagamento*) authorized by the BCB.

Integrating Large Language Models (LLMs) into financial services workloads introduces specific operational and security considerations:
1. **Data Loss Prevention & Confidentiality**: Inadvertent transmission of Personally Identifiable Information (PII) such as Brazilian CPFs, CNPJs, bank account numbers, and transaction details to external cloud LLM providers.
2. **Provider Dependability & Operational Continuity**: Single-provider outages or latency spikes impact service continuity, requiring multi-provider abstraction strategies.
3. **Cross-Border Cloud Governance**: When using cloud LLM APIs hosted abroad, institutions must maintain compliance with regulatory oversight and confidentiality directives. Ingress PII redaction serves as a technical confidentiality risk reduction control, though it is not a legal substitute for cloud contracting compliance.
4. **Auditability & Traceability**: End-to-end traceability of AI inference requests with persistent correlation identifiers and structured audit logging.

## Decision
We deploy the **Kong AI Gateway** as an AI Control Plane and Data Plane in front of LLM workloads to implement **technical control building blocks**. 

> [!NOTE]
> **Legal Framing & Scope Notice**:
> These technical controls support institutional compliance programs, but software alone cannot "guarantee" or "certify" compliance with BCB regulations. Regulatory compliance is an institutional attribute that requires qualified legal counsel, vendor risk management, operational incident tracking, and governance processes.

The architecture implements the following technical mechanisms:

### 1. Dual-Layer PII Interception & Obfuscation
- Pre-request payload inspection using a custom non-blocking Lua plugin (`bcb-pii-sanitizer`) combined with a dedicated Python microservice (`pii-sanitizer`).
- Automated detection of Brazilian CPFs and CNPJs gated by mathematical checksum verification (`validate_cpf_digits`, `validate_cnpj_digits`), alongside pattern-based detection for bank accounts, monetary amounts, phone numbers, and email addresses.
- While heuristic regex and checksum filtering significantly reduce accidental data leakage, they do not provide mathematical certainty against arbitrary unstructured or adversarial prompt structures.
- Support for both `placeholder` (`[REDACTED_CPF_1]`) and `synthetic` mode (generating mathematically valid synthetic credentials to preserve LLM reasoning context).

### 2. Multi-Provider LLM Abstraction
- Kong `ai-proxy` provides unified multi-provider abstraction across different LLM backends:
  - **Primary**: OpenAI / Azure OpenAI
  - **Secondary**: AWS Bedrock
  - **Tertiary**: Local Llama 3 via Ollama (On-premises / air-gapped)
- *Note on Failover*: `ai-proxy` abstracts provider routing and API translation. However, automated runtime failover between heterogeneous providers with differing parameter schemas and response formats requires external orchestration or custom plugins not fully implemented in the baseline gateway configuration.

### 3. FinOps & OWASP LLM Mitigation
- **Prompt Guardrails (`ai-prompt-guard`)**: Intercepts direct/indirect prompt injection attempts (OWASP LLM01:2025) in both OSS and Enterprise editions.
- **Semantic Caching (`ai-semantic-cache`)**: Powered by Redis Vector Search (cosine similarity > 0.85) to eliminate duplicate upstream LLM calls, cutting latency and API costs. (*Requires Kong Enterprise license*).
- **Token-Based Rate Limiting (`ai-rate-limiting-advanced`)**: Enforces consumption budgets calculated on LLM token counts (`gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens`), mitigating OWASP LLM10:2025 Denial of Wallet. (*Requires Kong Enterprise license*).

### 4. OpenTelemetry & Structured Auditability
- Trace correlation via `correlation-id` injecting standard `X-Request-ID` headers.
- OpenTelemetry GenAI instrumentation with collector attribute redaction (`attributes/redact_genai`) for APM spans and companion `bcb-otel-scrubber` Lua plugin for log serialization.
- Structured JSON audit log outputs serialized via `file-log` (`/tmp/audit-logs/kong-audit.log`).
- *Note on Audit Integrity*: Local filesystem logs are mutable; production compliance requires piping these logs to off-host, tamper-evident WORM (Write Once, Read Many) storage (e.g., AWS S3 Object Lock, Azure Immutable Blob) to establish non-repudiation.

## Consequences
- **Positive**: Provides structured technical controls for data confidentiality, prompt inspection, telemetry scrubbing, and structured audit logging; decouples client applications from specific LLM provider APIs.
- **Positive**: Establishes a transparent separation between open-source community capabilities and enterprise-licensed features.
- **Qualifications**:
  - Technical building blocks only: does not certify legal or institutional regulatory compliance.
  - Runtime failover between heterogeneous providers requires external orchestration.
  - Audit logs written to local disk require forwarding to off-host WORM storage for non-repudiation.
