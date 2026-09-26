"""
PII Sanitizer & Mock LLM Controller — BCB CMN 4893/21 & BCB 85/21 Compliance
=============================================================================
FastAPI microservice for real-time Brazilian PII detection, redaction,
and synthetic generation. Provides mock LLM completion endpoints with token
usage metrics and RFC 7807 Problem Details error formatting.
"""

import os
import time
import logging
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.schemas import (
    SanitizeRequest,
    SanitizeResponse,
    ReidentifyRequest,
    ReidentifyResponse,
    HealthResponse,
    ProblemDetails,
)
from app.pii_engine import detect_and_sanitize, normalize_entity_key
from app.token_vault import GLOBAL_TOKEN_VAULT
from app.metrics import GLOBAL_METRICS

# ── Logging Setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pii-sanitizer")

# ── App Initialization ────────────────────────────────────────────────────────

app = FastAPI(
    title="PII Sanitizer & LLM Mock — BCB Compliance Engine",
    description=(
        "Production-grade PII detection and mock LLM service supporting "
        "Resolução CMN 4893/21 and BCB 85/21 financial regulatory compliance."
    ),
    version="2.0.0",
)

# ── Thread-Safe Global State for Mock LLM ─────────────────────────────────────

last_llm_request: Dict[str, Any] = {
    "payload": None,
    "timestamp": None,
}

SESSION_SYNTHETIC_CACHE: Dict[str, Dict[str, str]] = {}
MAX_SESSION_CACHE_SIZE = 1000


# ── RFC 7807 Problem Details Error Handlers ────────────────────────────────────


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Formats validation errors as RFC 7807 Problem Details."""
    problem = ProblemDetails(
        type="https://tools.ietf.org/html/rfc7807#section-3.1",
        title="Bad Request - Validation Error",
        status=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
        instance=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=problem.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Prevents stack traces from leaking to end-users (RFC 7807 compliance)."""
    logger.error("Unhandled Exception: %s", str(exc), exc_info=True)
    problem = ProblemDetails(
        type="https://tools.ietf.org/html/rfc7807#section-3.1",
        title="Internal Server Error",
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An internal processing error occurred. Please contact compliance audit.",
        instance=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


# ── REST API Endpoints ────────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse, tags=["Operational"])
async def health_check():
    """Health check endpoint for container readiness probes."""
    GLOBAL_METRICS.record_request("/health", 200, 0.0)
    return HealthResponse()


@app.get("/metrics", tags=["Operational"])
async def prometheus_metrics():
    """
    Exposes real-time Prometheus text metrics for APM, Prometheus scraper,
    OpenTelemetry Collector, and Kubernetes ServiceMonitor.
    """
    metrics_text = GLOBAL_METRICS.generate_prometheus_text(
        active_vault_sessions=GLOBAL_TOKEN_VAULT.active_sessions_count,
        total_vault_tokens=GLOBAL_TOKEN_VAULT.total_tokens_count,
    )
    return Response(
        content=metrics_text,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post("/sanitize", response_model=SanitizeResponse, tags=["PII Engine"])
async def sanitize_text(request_data: SanitizeRequest):
    """
    Performs real-time text analysis to intercept and redact Brazilian PII data.
    """
    if not request_data.text or not request_data.text.strip():
        GLOBAL_METRICS.record_request("/sanitize", 400, 0.0)
        problem = ProblemDetails(
            type="https://tools.ietf.org/html/rfc7807#section-3.1",
            title="Bad Request",
            status=status.HTTP_400_BAD_REQUEST,
            detail="The input 'text' field cannot be empty.",
            instance="/sanitize",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=problem.model_dump(exclude_none=True),
            headers={"Content-Type": "application/problem+json"},
        )

    session_map: Optional[Dict[str, str]] = None
    if request_data.session_id:
        session_vault = GLOBAL_TOKEN_VAULT.get_or_create_session(request_data.session_id)
        session_map = session_vault.forward_map

    result = detect_and_sanitize(
        request_data.text,
        request_data.redact_type,
        entity_map=session_map,
    )

    if request_data.session_id:
        for entity in result.pii_detected:
            canon_key = normalize_entity_key(entity.type, entity.original)
            GLOBAL_TOKEN_VAULT.record_entity(
                request_data.session_id,
                canon_key,
                entity.original,
                entity.replacement,
            )

    GLOBAL_METRICS.record_request("/sanitize", 200, result.processing_time_ms / 1000.0)

    if result.total_entities > 0:
        entity_counts: Dict[str, int] = {}
        for entity in result.pii_detected:
            entity_counts[entity.type] = entity_counts.get(entity.type, 0) + 1
        GLOBAL_METRICS.record_entities(entity_counts)

        logger.info(
            "PII Intercepted: %d entities [%s] | latency: %.2fms",
            result.total_entities,
            ", ".join(e.type for e in result.pii_detected),
            result.processing_time_ms,
        )

    return result


@app.post("/re-identify", response_model=ReidentifyResponse, tags=["Token Vault"])
@app.post("/de-anonymize", response_model=ReidentifyResponse, tags=["Token Vault"])
async def reidentify_text(request_data: ReidentifyRequest):
    """
    Restores original sensitive entities from replacement placeholders or synthetic values
    using the session's tokenization vault. Enables authorized egress re-identification.
    """
    start_time = time.perf_counter()
    if not request_data.text or not request_data.text.strip():
        GLOBAL_METRICS.record_request("/re-identify", 400, 0.0)
        problem = ProblemDetails(
            type="https://tools.ietf.org/html/rfc7807#section-3.1",
            title="Bad Request",
            status=status.HTTP_400_BAD_REQUEST,
            detail="The input 'text' field cannot be empty.",
            instance="/re-identify",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=problem.model_dump(exclude_none=True),
            headers={"Content-Type": "application/problem+json"},
        )

    restored_text, count = GLOBAL_TOKEN_VAULT.reidentify(
        request_data.session_id,
        request_data.text,
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    GLOBAL_METRICS.record_request("/re-identify", 200, elapsed_ms / 1000.0)

    logger.info(
        "Re-identification executed for session %s: restored %d entities | latency: %.2fms",
        request_data.session_id,
        count,
        elapsed_ms,
    )

    return ReidentifyResponse(
        reidentified_text=restored_text,
        restored_entities=count,
        session_id=request_data.session_id,
        processing_time_ms=round(elapsed_ms, 2),
    )


# ── Mock LLM & Testing Endpoints ──────────────────────────────────────────────


def is_mock_llm_enabled() -> bool:
    """Checks whether Mock LLM and test probe endpoints are enabled."""
    val = os.getenv("ENABLE_MOCK_LLM", "true").strip().lower()
    return val in ("true", "1", "t", "yes", "y")


def mock_disabled_response(path: str) -> JSONResponse:
    """Returns RFC 7807 404 Not Found when mock LLM routes are disabled in production."""
    problem = ProblemDetails(
        type="https://tools.ietf.org/html/rfc7807#section-3.1",
        title="Not Found",
        status=status.HTTP_404_NOT_FOUND,
        detail="Mock LLM endpoints are disabled in this environment (ENABLE_MOCK_LLM=false).",
        instance=path,
    )
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content=problem.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


@app.post("/mock-llm/v1/chat/completions", tags=["Mock LLM"])
@app.post("/mock-llm", tags=["Mock LLM"])
async def mock_llm_completion(request: Request):
    """
    Mock LLM completions endpoint mimicking OpenAI/Bedrock payloads.
    Calculates token counts for OWASP LLM10:2025 rate-limiting verification.
    """
    if not is_mock_llm_enabled():
        return mock_disabled_response(request.url.path)

    try:
        body_json = await request.json()
    except Exception:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8") if isinstance(body_bytes, bytes) else str(body_bytes)
        body_json = {"raw_payload": body_str}

    last_llm_request["payload"] = body_json
    last_llm_request["timestamp"] = time.time()

    logger.info("Mock LLM received request payload: %s", str(body_json)[:300])

    prompt_tokens = 25
    completion_tokens = 35

    return {
        "id": "chatcmpl-mock-bcb-4893-21",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "mock-compliance-llm",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Compliance verification: Safe response generated by Mock LLM under BCB CMN 4893/21.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


@app.get("/mock-llm/last-request", tags=["Mock LLM"])
async def get_last_llm_request():
    """Retrieves the last request payload received by the mock LLM."""
    if not is_mock_llm_enabled():
        return mock_disabled_response("/mock-llm/last-request")
    return last_llm_request


@app.post("/mock-llm/reset", tags=["Mock LLM"])
async def reset_last_llm_request():
    """Resets mock LLM state and session pseudonymization cache."""
    if not is_mock_llm_enabled():
        return mock_disabled_response("/mock-llm/reset")
    last_llm_request["payload"] = None
    last_llm_request["timestamp"] = None
    GLOBAL_TOKEN_VAULT.clear()
    SESSION_SYNTHETIC_CACHE.clear()
    logger.info("Mock LLM state, session cache, and token vault reset.")
    return {"status": "reset"}


@app.get("/", tags=["Operational"])
async def root():
    """Root landing route."""
    endpoints = {
        "sanitize": "POST /sanitize",
        "reidentify": "POST /re-identify",
        "health": "GET /health",
    }
    if is_mock_llm_enabled():
        endpoints.update({
            "mock_llm": "POST /mock-llm/v1/chat/completions",
            "mock_llm_last_request": "GET /mock-llm/last-request",
            "mock_llm_reset": "POST /mock-llm/reset",
        })
    return {
        "service": "PII Sanitizer & Mock LLM Controller",
        "version": "2.0.0",
        "compliance": "BCB CMN 4893/21 & BCB 85/21",
        "docs": "/docs",
        "endpoints": endpoints,
    }


if __name__ == "__main__":
    import uvicorn
    from pathlib import Path

    port = int(os.getenv("PORT", "8443"))
    ssl_keyfile = os.getenv("SSL_KEYFILE")
    ssl_certfile = os.getenv("SSL_CERTFILE")

    # Fallback to local certs directory if present
    if not ssl_keyfile or not ssl_certfile:
        base_dir = Path(__file__).resolve().parent.parent
        dev_key = base_dir / "certs" / "dev-key.pem"
        dev_cert = base_dir / "certs" / "dev-cert.pem"
        if dev_key.exists() and dev_cert.exists():
            ssl_keyfile = str(dev_key)
            ssl_certfile = str(dev_cert)

    ssl_kwargs = {}
    if ssl_keyfile and ssl_certfile and os.path.exists(ssl_keyfile) and os.path.exists(ssl_certfile):
        ssl_kwargs["ssl_keyfile"] = ssl_keyfile
        ssl_kwargs["ssl_certfile"] = ssl_certfile
        logger.info("Starting PII Sanitizer over TLS on port %d", port)
    else:
        logger.warning("No TLS certificates found, falling back to plaintext on port %d", port)

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
        **ssl_kwargs,
    )
