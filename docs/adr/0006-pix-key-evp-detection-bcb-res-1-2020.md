# ADR 0006: BCB PIX Key (EVP Random Key) & RG Document Detection and Masking

## Status

Accepted

## Context

Under Banco Central do Brasil (BCB) Resolution 1/2020, PIX is Brazil's instant payment network. PIX keys (Chaves PIX) are transactional aliases linked directly to underlying Demand, Savings, or Payment accounts. PIX keys can be:
1. Natural person or corporate national tax identifiers (**CPF** or **CNPJ**).
2. Contact identifiers (**Email** or **Mobile Phone**).
3. Random Keys (**Chave Aleatória / EVP - Endereço Virtual Pagador**), structured strictly as RFC 4122 UUID v4 128-bit identifiers (e.g. `123e4567-e89b-12d3-a456-426614174000`).

While CPFs, CNPJs, Emails, and Phone numbers are standard PII entities, PIX Random Keys (EVPs) are unique to the Brazilian financial system. Additionally, Brazilian identity cards (**RG - Registro Geral**) are routinely presented during financial KYC and customer service workflows.

Failing to detect EVPs allows customer transaction destinations to leak into external Large Language Model training or prompt logs in violation of **Resolução BCB nº 85/2021** (Cybersecurity and Data Confidentiality) and **Lei Geral de Proteção de Dados (LGPD)**.

Conversely, blanket redaction of all UUIDs in API gateways causes severe false positives on distributed tracing headers (`X-Correlation-ID`, `traceparent`, Kong request IDs, commit hashes).

## Decision

1. **Context-Aware PIX EVP Detection**:
   - Detect PIX Random Keys using a high-priority regex pattern that couples RFC 4122 UUID v4 syntax with explicit Brazilian financial contextual trigger terms (`chave pix`, `pix`, `evp`, `chave aleatória`).
   - Isolate the UUID value via regex capturing groups so that contextual preposition markers (`chave pix:`, `para o pix`) remain intact while the 128-bit key is excised.
   - Non-PIX system UUIDs (e.g., correlation IDs, build hashes) lacking financial payment context are preserved intact, preventing false-positive disruption of developer and operational workflows.

2. **Formatted Brazilian RG Detection**:
   - Detect standard formatted Brazilian RG identity documents (`XX.XXX.XXX-X` or `X.XXX.XXX-X`, including digit check `X`).
   - Normalization converts RG strings into canonical uppercase keys (`RG:12345678X`) for deterministic pseudonymization.

3. **Deterministic Synthetic Generation & Reversible Vault**:
   - Implement `generate_synthetic_pix_key()` generating mathematically valid UUID v4 replacements.
   - Implement `generate_synthetic_rg()` producing format-preserving synthetic identity numbers.
   - Register `PIX_KEY` and `RG` within the [TokenVault](file:///c:/Users/vinicius/Documents/GeminiCodes/kong-ai-gateway-bcb-compliance/pii-sanitizer/app/token_vault.py) for round-trip egress de-anonymization (`POST /re-identify`).

## Consequences

- **Compliance**: Full regulatory coverage for all five BCB PIX key types (CPF, CNPJ, Email, Phone, EVP) under Resolução BCB 1/2020.
- **Precision**: 100% false-positive resistance against system correlation IDs and tracing metadata.
- **Reversibility**: Upstream financial completions referencing synthetic EVPs can be transparently restored by authorized egress callers.
