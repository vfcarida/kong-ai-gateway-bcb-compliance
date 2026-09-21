# ADR 0003: Session-Consistent Deterministic Synthetic Entity Pseudonymization

## Status
Accepted

## Context
The PII sanitizer microservice (`pii-sanitizer`) supports two redaction modes:
- **`placeholder`**: Replaces each detected entity with a labeled token (e.g., `[REDACTED_CPF_1]`), unambiguous but opaque to LLM reasoning.
- **`synthetic`**: Generates mathematically valid but fictitious replacement entities (e.g., a valid CPF with correct Modulus-11 check digits, a credible synthetic name, a realistic bank account number) to preserve the semantic context and reasoning capability of the downstream LLM.

Two categories of consistency defects were identified in the original implementation:

### Defect 1: Intra-Prompt Inconsistency
When a text prompt contained repeated occurrences of the same CPF (e.g., a customer CPF mentioned twice in the same message), the previous `_get_synthetic()` function was called independently for each match occurrence, producing distinct random synthetic CPFs. This caused LLM reasoning errors: the model would interpret two different synthetic CPFs as two different customers, breaking referential integrity in contexts such as:
> _"Transferência do CPF 123.456.789-09 para o mesmo titular do CPF 123.456.789-09"_

### Defect 2: Format-Parity Inconsistency
A raw 11-digit CPF (`12345678909`) and its formatted counterpart (`123.456.789-09`) in the same prompt referred to identical entities but received differently formatted synthetic replacements, making it impossible to correlate them.

### Defect 3: Cross-Turn Session Inconsistency
In multi-turn conversational contexts (e.g., iterative LLM chat), the same customer CPF appearing in turn 1 and referenced again in turn 2 received entirely different synthetic replacements in each API call, breaking the conversation's referential consistency from the LLM's perspective.

## Decision

We implement **deterministic session-consistent synthetic entity pseudonymization** using a three-layer canonical identity resolution strategy:

### Layer 1: Canonical Entity Key Normalization (`normalize_entity_key`)
Before assigning any synthetic replacement, each detected entity is normalized to a canonical key that strips formatting while preserving identity:

```python
# CPF: 123.456.789-09 → "CPF:12345678909"
# CPF: 12345678909    → "CPF:12345678909"
# EMAIL: Test@Banco.COM.BR → "EMAIL:test@banco.com.br"
# PHONE: (11) 98765-4321 → "PHONE:11987654321"
```

This ensures that `123.456.789-09` and `12345678909` are recognized as the same entity within a text pass.

### Layer 2: Intra-Prompt Pre-Assignment (`detect_and_sanitize` step 4)
Before applying any replacements, `detect_and_sanitize` iterates over all filtered matches in forward order, pre-assigning synthetic values into a `synthetic_map: Dict[str, str]`. Subsequent occurrences of an entity with the same canonical key reuse the already-assigned replacement:

```python
for pii_type, start, end, value, _, _ in filtered_matches:
    canon_key = normalize_entity_key(pii_type, value)
    if canon_key not in synthetic_map:
        synthetic_map[canon_key] = _get_synthetic(pii_type)
```

### Layer 3: Format-Aware Synthetic Output (`_format_synthetic`)
After resolving a shared canonical synthetic value, the output is formatted to match the original entity's presentation style:
- Raw 11-digit CPF → receives raw digits from the formatted synthetic CPF
- Formatted `XXX.XXX.XXX-XX` CPF → receives the fully formatted synthetic CPF

```python
def _format_synthetic(pii_type, raw_synthetic, original_value):
    if pii_type in ("CPF", "CNPJ"):
        if re.match(r"^\d+$", original_value):
            return re.sub(r"\D", "", raw_synthetic)  # strip punctuation
    return raw_synthetic
```

### Cross-Turn Session Consistency (`session_id`)
An optional `session_id` field is added to the `/sanitize` API request payload. When provided:
1. The server maintains a per-session `SESSION_SYNTHETIC_CACHE: Dict[str, Dict[str, str]]` dictionary.
2. The session's accumulated `entity_map` is passed to `detect_and_sanitize`, seeding the `synthetic_map` with all entities already encountered during earlier turns.
3. The updated map is written back to the session cache after each request.
4. Session caches are evicted using an LRU-approximation strategy (oldest key removed when `MAX_SESSION_CACHE_SIZE = 1000` is reached).

The session cache is cleared when `POST /mock-llm/reset` is called, maintaining test isolation.

## Consequences

- **Positive**: Eliminates referential integrity failures in multi-occurrence and multi-turn LLM interactions. The LLM consistently reasons about the same pseudonymized entity, enabling coherent responses.
- **Positive**: Format parity ensures that raw and formatted representations of the same entity map to consistent synthetic replacements, preventing correlation attacks via format variation.
- **Positive**: The canonical key normalization is deterministic per-request; it does not persist across requests (unless `session_id` is provided), meaning different requests for the same original entity produce different synthetic values — preserving k-anonymity properties across sessions.
- **Trade-off**: Session caches consume memory. The `MAX_SESSION_CACHE_SIZE` limit of 1,000 concurrent sessions bounds maximum memory overhead. Production deployments with high session cardinality should consider an external distributed cache (e.g., Redis with configurable TTL).
- **Trade-off**: The canonical key is computed in-process memory. The `entity_map` is not persisted to disk; if the service restarts, cross-session consistency for long-running conversations is lost. This is acceptable for the reference implementation but should be addressed in production-hardened deployments.
- **Qualification**: This architecture addresses consistent pseudonymization within a single service instance. Horizontally scaled deployments (multiple `pii-sanitizer` replicas) must share session state via an external cache to maintain cross-instance consistency.

## Tests

Three automated unit tests validate this ADR's guarantees:

| Test | Guarantee Verified |
|---|---|
| `test_synthetic_consistency_repeated_cpf_in_single_prompt` | Same CPF appearing twice in one prompt receives identical synthetic replacement |
| `test_synthetic_consistency_format_awareness` | Formatted and raw representations of the same CPF are assigned consistent synthetic values with format parity |
| `test_synthetic_consistency_session_id` | Same CPF appearing across two sequential `/sanitize` calls with the same `session_id` receives the same synthetic value in both turns |
