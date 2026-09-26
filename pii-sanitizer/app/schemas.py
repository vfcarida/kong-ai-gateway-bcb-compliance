"""
Pydantic Schemas & RFC 7807 Problem Details Models
===================================================
Models for request/response payloads, PII entity tracking, operational health,
and RFC 7807 HTTP Problem Details error structures.
"""

from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class RedactType(str, Enum):
    PLACEHOLDER = "placeholder"
    SYNTHETIC = "synthetic"


class SanitizeRequest(BaseModel):
    """Payload sent to the PII sanitization endpoint."""
    text: str = Field(..., description="Raw text prompt to analyze and sanitize")
    redact_type: RedactType = Field(
        default=RedactType.PLACEHOLDER,
        description="Type of redaction: 'placeholder' or 'synthetic'",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Optional session or conversation ID for cross-request consistent pseudonymization",
    )


class PIIEntity(BaseModel):
    """Details of a single detected PII entity."""
    type: str = Field(..., description="Category of PII (CPF, CNPJ, CREDIT_CARD, BANK_ACCOUNT, EMAIL, PHONE, NAME, MONEY)")
    original: str = Field(..., description="Matched original sensitive string")
    replacement: str = Field(..., description="Obfuscated replacement string applied")
    start: int = Field(..., description="Start character offset")
    end: int = Field(..., description="End character offset")
    checksum_valid: Optional[bool] = Field(
        default=None,
        description="Result of checksum validation for CPF/CNPJ/CREDIT_CARD (None if not applicable)",
    )


class SanitizeResponse(BaseModel):
    """Result of the PII sanitization processing."""
    sanitized_text: str = Field(..., description="Sanitized text prompt")
    pii_detected: List[PIIEntity] = Field(
        default_factory=list, description="List of detected PII entities"
    )
    total_entities: int = Field(0, description="Total entity count detected")
    processing_time_ms: float = Field(
        0.0, description="Processing latency in milliseconds"
    )
    redact_type: str = Field("placeholder", description="Applied redaction mode")


class ReidentifyRequest(BaseModel):
    """Payload sent to the re-identification / de-anonymization endpoint."""
    text: str = Field(..., description="Sanitized text containing tokens or synthetic values to restore")
    session_id: str = Field(..., description="Session ID holding the token vault mappings")


class ReidentifyResponse(BaseModel):
    """Result of re-identification process."""
    reidentified_text: str = Field(..., description="Text with original PII values restored")
    restored_entities: int = Field(0, description="Number of tokens/entities restored")
    session_id: str = Field(..., description="Session ID used for vault lookup")
    processing_time_ms: float = Field(0.0, description="Processing latency in milliseconds")


class HealthResponse(BaseModel):
    """Health check operational status."""
    status: str = "healthy"
    service: str = "pii-sanitizer-mock-llm"
    version: str = "2.0.0"
    compliance: str = "BCB CMN 4893/21 & BCB 85/21"


class ProblemDetails(BaseModel):
    """
    RFC 7807 Problem Details for HTTP APIs.
    Prevents leakage of internal stack traces.
    """
    type: str = Field("https://tools.ietf.org/html/rfc7807", description="URI reference identifying problem type")
    title: str = Field(..., description="Short human-readable summary of problem")
    status: int = Field(..., description="HTTP status code")
    detail: str = Field(..., description="Human-readable explanation specific to this occurrence")
    instance: Optional[str] = Field(None, description="URI reference identifying specific occurrence of problem")
