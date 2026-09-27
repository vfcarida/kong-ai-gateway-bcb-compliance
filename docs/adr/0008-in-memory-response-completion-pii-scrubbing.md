# ADR 0008: In-Memory Egress Completion Scrubbing and Streaming Response Protection (FEAT-03)

## Status

Accepted

## Context

Under **Resolução BCB nº 85/2021** (Confidentiality and Cybersecurity for Payment Institutions) and **Resolução CMN nº 4.893/2021**, financial institutions are required to safeguard customer personal and financial data across the entire processing lifecycle.

While ingress PII sanitization (via `bcb-pii-sanitizer` and the `pii-sanitizer` sidecar) ensures that customer prompts dispatched upstream are obfuscated, downstream client applications remain vulnerable to **model-echoed PII and sensitive data regurgitation**:
1. Large Language Models summarizing multi-turn dialogues or retrieving external RAG chunks may echo sensitive credentials (e.g., repeating a CPF, bank account, or payment card).
2. Malicious prompt injection attacks may elicit model hallucination of real customer accounts.
3. In Nginx/OpenResty, the `body_filter_by_lua` phase executes within the output filter chain where asynchronous cosockets / network I/O are disabled by the Lua runtime ("API disabled in the context of body_filter"). Calling an external sidecar microservice from `body_filter` is architecturally impossible.

## Decision

1. **Pure In-Memory Lua Redaction Engine (`checksum.lua`)**:
   - Implemented `_M.sanitize_text_in_memory(text, redact_type)` entirely within native LuaJIT.
   - Evaluates Modulo-11 check digits for Brazilian CPFs and CNPJs, and ISO/IEC 7812 Luhn check digits for payment card PANs.
   - Replaces valid entities with redaction placeholders (`[REDACTED_CPF]`, `[REDACTED_CNPJ]`, `[REDACTED_CARD]`, `[REDACTED_PHONE]`, `[REDACTED_EMAIL]`, `[REDACTED_PIX_KEY]`).
   - Executes with zero cosockets, zero external network dependencies, and `< 0.1ms` latency.

2. **Dual-Phase Output Interception in Gateway (`handler.lua`)**:
   - **`header_filter(config)`**: Inspects `Content-Type` for `application/json`, `text/event-stream`, or `text/plain`. When `config.scrub_response: true` is enabled, flags `ngx.ctx.bcb_scrub_response = true` and clears the `Content-Length` header (`ngx.header["Content-Length"] = nil`), allowing downstream chunk size mutation without HTTP truncation errors.
   - **`body_filter(config)`**: Intercepts response chunks `ngx.arg[1]`. If `ngx.ctx.bcb_scrub_response` is active, passes chunks through `checksum.sanitize_text_in_memory`, rewriting outgoing chunks in-flight before transmission to client applications.

3. **Opt-In Response Filtering in Schema (`schema.lua`)**:
   - Added `scrub_response` boolean configuration parameter (default: `false` for exact backward compatibility; set to `true` on protected egress routes).

## Consequences

- **Egress Perimeter Defense**: Prevents model-echoed PII from leaking back to client applications or mobile frontends.
- **Architectural Soundness**: Strictly honors OpenResty runtime constraints by avoiding cosocket invocations in `body_filter`.
- **Streaming Compatibility**: Safely inspects and sanitizes Server-Sent Events (`text/event-stream`) and standard JSON completion payloads.
- **Zero Overhead**: When disabled, passes responses through with zero processing overhead.
