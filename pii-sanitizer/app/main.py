"""
PII Sanitizer & Mock LLM Service — Kong AI Gateway PoC
======================================================
FastAPI service for real-time detection and obfuscation of Personally
Identifiable Information (PII) with a focus on Brazilian data patterns,
aligned with Resolution BCB No. 538/2025.

Also provides a mock LLM completion endpoint to completely decouple
local testing environments from external cloud providers (AWS Bedrock/OpenAI).
"""

import os
import re
import random
import time
import logging
from typing import Optional, List, Dict, Any
from enum import Enum

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# ── Logging Setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pii-sanitizer")

# ── App Initialization ────────────────────────────────────────────────────────

app = FastAPI(
    title="PII Sanitizer & LLM Mock — BCB 538/2025 Compliance",
    description=(
        "PII detection/obfuscation service and mock LLM provider for local testing. "
        "Focuses on Brazilian CPFs, phone numbers, emails, names, and monetary values."
    ),
    version="2.0.0",
)

# ── Thread-Safe Global State for LLM Mocks ────────────────────────────────────

# Stores the last request payload received by the mock LLM for E2E validation.
last_llm_request: Dict[str, Any] = {
    "payload": None,
    "timestamp": None,
}

# ── Pydantic Models ───────────────────────────────────────────────────────────


class RedactType(str, Enum):
    PLACEHOLDER = "placeholder"
    SYNTHETIC = "synthetic"


class SanitizeRequest(BaseModel):
    """Request payload for text sanitization."""
    text: str = Field(..., description="The raw input text to analyze and sanitize")
    redact_type: RedactType = Field(
        default=RedactType.PLACEHOLDER,
        description="Type of redaction to apply: placeholder or synthetic",
    )


class PIIEntity(BaseModel):
    """Detailed metadata for a single detected PII entity."""
    type: str = Field(..., description="Type of PII (e.g., CPF, EMAIL, PHONE, NAME, MONEY)")
    original: str = Field(..., description="The original sensitive value matched")
    replacement: str = Field(..., description="The obfuscated value applied in place")
    start: int = Field(..., description="Start character index in the original text")
    end: int = Field(..., description="End character index in the original text")


class SanitizeResponse(BaseModel):
    """Sanitization response including audit metadata for compliance reports."""
    sanitized_text: str = Field(..., description="Sanitized text with PII redacted")
    pii_detected: List[PIIEntity] = Field(
        default_factory=list, description="List of all detected PII entities"
    )
    total_entities: int = Field(0, description="Total number of PII entities detected")
    processing_time_ms: float = Field(
        0.0, description="Time taken to process the request in milliseconds"
    )
    redact_type: str = Field("placeholder", description="Redaction method utilized")


class HealthResponse(BaseModel):
    """System health check response."""
    status: str = "healthy"
    service: str = "pii-sanitizer-mock-llm"
    version: str = "2.0.0"


# ── PII Detection Engine ────────────────────────────────────────────────────


def _validate_cpf_digits(cpf_digits: str) -> bool:
    """
    Validates a Brazilian CPF checksum digits.
    Returns True if mathematically valid, False otherwise.
    """
    if len(cpf_digits) != 11:
        return False

    # Exclude CPFs with all identical digits (e.g., 111.111.111-11)
    if cpf_digits == cpf_digits[0] * 11:
        return False

    # First verification digit calculation
    total = sum(int(cpf_digits[i]) * (10 - i) for i in range(9))
    remainder = total % 11
    first_check = 0 if remainder < 2 else 11 - remainder
    if int(cpf_digits[9]) != first_check:
        return False

    # Second verification digit calculation
    total = sum(int(cpf_digits[i]) * (11 - i) for i in range(10))
    remainder = total % 11
    second_check = 0 if remainder < 2 else 11 - remainder
    if int(cpf_digits[10]) != second_check:
        return False

    return True


def _generate_synthetic_cpf() -> str:
    """Generates a mathematically valid, synthetic Brazilian CPF (XXX.XXX.XXX-XX)."""
    digits = [random.randint(0, 9) for _ in range(9)]

    # First checksum digit
    total = sum(digits[i] * (10 - i) for i in range(9))
    remainder = total % 11
    digits.append(0 if remainder < 2 else 11 - remainder)

    # Second checksum digit
    total = sum(digits[i] * (11 - i) for i in range(10))
    remainder = total % 11
    digits.append(0 if remainder < 2 else 11 - remainder)

    s = "".join(str(d) for d in digits)
    return f"{s[:3]}.{s[3:6]}.{s[6:9]}-{s[9:]}"


def _generate_synthetic_email() -> str:
    """Generates a realistic, synthetic email address."""
    names = ["user", "contact", "client", "admin", "support", "manager"]
    domains = ["example.com.br", "domain.com", "test.org.br", "sandbox.net"]
    return f"{random.choice(names)}{random.randint(100, 999)}@{random.choice(domains)}"


def _generate_synthetic_phone() -> str:
    """Generates a realistic, synthetic Brazilian phone number."""
    ddd = random.randint(11, 99)
    num = random.randint(90000, 99999)
    suffix = random.randint(1000, 9999)
    return f"({ddd}) {num}-{suffix}"


def _generate_synthetic_name() -> str:
    """Generates a realistic, synthetic Brazilian name."""
    first_names = ["Carlos", "Ana", "Pedro", "Mariana", "Lucas", "Juliana", "Rafael", "Beatriz"]
    last_names = ["Ferreira", "Souza", "Costa", "Almeida", "Pereira", "Barbosa", "Silva", "Santos"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def _generate_synthetic_money() -> str:
    """Generates a synthetic Brazilian Real currency value."""
    value = random.randint(100, 99999)
    return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


# Ordered PII detection patterns (more specific patterns go first)
PII_PATTERNS: List[tuple[str, re.Pattern, int]] = [
    # Formatted Brazilian CPF: 123.456.789-00
    (
        "CPF",
        re.compile(r"\d{3}\.\d{3}\.\d{3}-\d{2}"),
        0,
    ),
    # Raw numeric CPF: 12345678900 (11 exact digits with word boundaries)
    (
        "CPF",
        re.compile(r"\b\d{11}\b"),
        1,
    ),
    # Email addresses
    (
        "EMAIL",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        0,
    ),
    # Brazilian phone numbers: (11) 99876-5432, 11 99876-5432, (11) 9876-5432, etc.
    (
        "PHONE",
        re.compile(r"\(?\d{2}\)?\s?\d{4,5}-?\d{4}"),
        0,
    ),
    # Currency values: R$ 50.000, R$ 1.234,56, etc.
    (
        "MONEY",
        re.compile(r"R\$\s?[\d.,]+"),
        0,
    ),
]

# Pattern for heuristic detection of Brazilian proper names (capitalized words)
NAME_PATTERN = re.compile(
    r"\b([A-ZÀ-Ú][a-zà-ú]{1,}(?:\s(?:da|de|do|dos|das|e)\s)?[A-ZÀ-Ú][a-zà-ú]{1,}(?:\s[A-ZÀ-Ú][a-zà-ú]{1,})*)\b"
)

# Common Portuguese stopwords/false-positives to filter out from name matches
NAME_STOPWORDS = {
    "Meu", "Minha", "Meus", "Minhas",
    "Seu", "Sua", "Seus", "Suas",
    "Nosso", "Nossa", "Nossos", "Nossas",
    "Este", "Esta", "Estes", "Estas",
    "Esse", "Essa", "Esses", "Essas",
    "Qual", "Quais", "Como", "Onde",
    "Posso", "Pode", "Podemos",
    "Para", "Pela", "Pelo",
    "Banco Central", "Sistema Financeiro",
    "Amazon Bedrock", "Kong Gateway",
}

# Pre-normalized set for O(1) stopword lookup (Optimization: eliminates O(M) sub-loop check)
NORMALIZED_STOPWORDS = {sw.lower() for sw in NAME_STOPWORDS}


def detect_and_sanitize(text: str, redact_type: RedactType) -> SanitizeResponse:
    """
    Scans, detects, and obfuscates PII in the given input text.

    Strategy:
    1. Scan input string with regex compiled patterns.
    2. Collect matches and their positions.
    3. Run optimized conflict resolution for overlapping matches.
    4. Perform string replacement in reverse order to preserve string indices.
    """
    start_time = time.perf_counter()
    entities: List[PIIEntity] = []
    counters: Dict[str, int] = {}
    raw_matches: List[tuple[str, int, int, str, int]] = []

    # 1. Regex scanning
    for pii_type, pattern, priority in PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()
            raw_matches.append((pii_type, match.start(), match.end(), value, priority))

    # 2. Proper name heuristic scanning
    for match in NAME_PATTERN.finditer(text):
        name = match.group()
        # Optimization: split words and lookup in the pre-normalized stopwords set (O(1) average lookup)
        name_lower = name.lower()
        words = name_lower.split()
        is_stopword = name_lower in NORMALIZED_STOPWORDS or any(w in NORMALIZED_STOPWORDS for w in words)
        
        if not is_stopword:
            raw_matches.append(("NAME", match.start(), match.end(), name, 10))

    # 3. Conflict resolution: sort by position ascending, then priority descending
    # Keeping the more specific match (lower priority integer means higher specificity)
    raw_matches.sort(key=lambda m: (m[1], -m[4]))
    filtered_matches: List[tuple[str, int, int, str, int]] = []
    last_end = -1

    for pii_type, start, end, value, priority in raw_matches:
        if start >= last_end:
            filtered_matches.append((pii_type, start, end, value, priority))
            last_end = end

    # 4. Generate obfuscated replacements (reverse order replacement preserves indices)
    sanitized = text
    for pii_type, start, end, value, _priority in reversed(filtered_matches):
        counters[pii_type] = counters.get(pii_type, 0) + 1
        idx = counters[pii_type]

        if redact_type == RedactType.SYNTHETIC:
            replacement = _get_synthetic_replacement(pii_type)
        else:
            replacement = f"[REDACTED_{pii_type}_{idx}]"

        entities.append(
            PIIEntity(
                type=pii_type,
                original=value,
                replacement=replacement,
                start=start,
                end=end,
            )
        )

        sanitized = sanitized[:start] + replacement + sanitized[end:]

    # Reverse the entities back to original chronological order of appearance
    entities.reverse()

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return SanitizeResponse(
        sanitized_text=sanitized,
        pii_detected=entities,
        total_entities=len(entities),
        processing_time_ms=round(elapsed_ms, 2),
        redact_type=redact_type.value,
    )


def _get_synthetic_replacement(pii_type: str) -> str:
    """Returns a dynamic synthetic mock value aligned with the requested PII type."""
    generators = {
        "CPF": _generate_synthetic_cpf,
        "EMAIL": _generate_synthetic_email,
        "PHONE": _generate_synthetic_phone,
        "NAME": _generate_synthetic_name,
        "MONEY": _generate_synthetic_money,
    }
    generator = generators.get(pii_type)
    return generator() if generator else f"[SYNTHETIC_{pii_type}]"


# ── REST API Endpoints ────────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse, tags=["Operational"])
async def health_check():
    """Health check endpoint for container clustering and readiness checks."""
    return HealthResponse()


@app.post("/sanitize", response_model=SanitizeResponse, tags=["PII Engine"])
async def sanitize_text(request: SanitizeRequest):
    """
    Performs real-time text analysis to intercept and redact Brazilian PII data.
    """
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="The input 'text' field cannot be empty.")

    result = detect_and_sanitize(request.text, request.redact_type)

    if result.total_entities > 0:
        logger.info(
            "PII Intercepted: %d entities [%s] | latency: %.2fms",
            result.total_entities,
            ", ".join(e.type for e in result.pii_detected),
            result.processing_time_ms,
        )

    return result


# ── Mock LLM & Testing Endpoints ──────────────────────────────────────────────


@app.post("/mock-llm/v1/chat/completions", tags=["Mock LLM"])
@app.post("/mock-llm", tags=["Mock LLM"])
async def mock_llm_completion(request: Request):
    """
    Mock LLM completions endpoint mimicking OpenAI/Bedrock.
    Captures request body for automated verification of compliance/sanitization.
    """
    body_json = None
    try:
        body_json = await request.json()
    except Exception:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8") if isinstance(body_bytes, bytes) else str(body_bytes)
        body_json = {"raw_payload": body_str}

    # Record request parameters to inspect PII interception state
    last_llm_request["payload"] = body_json
    last_llm_request["timestamp"] = time.time()

    logger.info("Mock LLM received request payload: %s", str(body_json)[:300])

    return {
        "id": "chatcmpl-mock-bcb-538-2025",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "mock-compliance-llm",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Compliance verification: This is a safe response generated by the local Mock LLM."
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": 15,
            "total_tokens": 30
        }
    }


@app.get("/mock-llm/last-request", tags=["Mock LLM"])
async def get_last_llm_request():
    """Retrieves the last request payload forwarded to the mock LLM."""
    return last_llm_request


@app.post("/mock-llm/reset", tags=["Mock LLM"])
async def reset_last_llm_request():
    """Resets the mock LLM request history to clean up testing states."""
    last_llm_request["payload"] = None
    last_llm_request["timestamp"] = None
    logger.info("Mock LLM state reset.")
    return {"status": "reset"}


@app.get("/", tags=["Operational"])
async def root():
    """Landing route returning service state and OpenAPI documentation pointers."""
    return {
        "service": "PII Sanitizer & Mock LLM Controller",
        "version": "2.0.0",
        "compliance": "BCB 538/2025",
        "docs": "/docs",
        "endpoints": {
            "sanitize": "POST /sanitize",
            "health": "GET /health",
            "mock_llm": "POST /mock-llm/v1/chat/completions",
            "mock_llm_last_request": "GET /mock-llm/last-request",
            "mock_llm_reset": "POST /mock-llm/reset"
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8088")),
        reload=False,
        log_level="info",
    )
