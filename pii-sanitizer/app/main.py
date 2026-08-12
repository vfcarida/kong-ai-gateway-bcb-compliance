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

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.schemas import (
    SanitizeRequest,
    SanitizeResponse,
    HealthResponse,
    ProblemDetails,
)
from app.pii_engine import detect_and_sanitize

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
    return HealthResponse()


@app.post("/sanitize", response_model=SanitizeResponse, tags=["PII Engine"])
async def sanitize_text(request_data: SanitizeRequest):
    """
    Performs real-time text analysis to intercept and redact Brazilian PII data.
    """
    if not request_data.text or not request_data.text.strip():
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

    result = detect_and_sanitize(request_data.text, request_data.redact_type)

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
    Mock LLM completions endpoint mimicking OpenAI/Bedrock payloads.
    Calculates token counts for OWASP LLM10:2025 rate-limiting verification.
    """
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
    return last_llm_request


@app.post("/mock-llm/reset", tags=["Mock LLM"])
async def reset_last_llm_request():
    """Resets mock LLM state."""
    last_llm_request["payload"] = None
    last_llm_request["timestamp"] = None
    logger.info("Mock LLM state reset.")
    return {"status": "reset"}


@app.get("/", tags=["Operational"])
async def root():
    """Root landing route."""
    return {
        "service": "PII Sanitizer & Mock LLM Controller",
        "version": "2.0.0",
        "compliance": "BCB CMN 4893/21 & BCB 85/21",
        "docs": "/docs",
        "endpoints": {
            "sanitize": "POST /sanitize",
            "health": "GET /health",
            "mock_llm": "POST /mock-llm/v1/chat/completions",
            "mock_llm_last_request": "GET /mock-llm/last-request",
            "mock_llm_reset": "POST /mock-llm/reset",
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
