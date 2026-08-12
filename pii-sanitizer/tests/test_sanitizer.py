"""
Pytest Suite — PII Sanitizer & Mock LLM Controller
===================================================
Automated unit tests validating PII detection, checksum verification,
RFC 7807 problem details, and mock LLM completion endpoints.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure app package is importable from pii-sanitizer root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.pii_engine import validate_cpf_digits, validate_cnpj_digits

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "BCB" in data["compliance"]


def test_validate_cpf_checksums():
    assert validate_cpf_digits("12345678909") is True
    assert validate_cpf_digits("11111111111") is False  # All identical digits
    assert validate_cpf_digits("12345678900") is False  # Invalid check digits


def test_validate_cnpj_checksums():
    assert validate_cnpj_digits("11222333000181") is True
    assert validate_cnpj_digits("00000000000000") is False


def test_sanitize_placeholder():
    payload = {
        "text": "My CPF is 123.456.789-00 and email is test@banco.com.br",
        "redact_type": "placeholder",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "[REDACTED_CPF_1]" in data["sanitized_text"]
    assert "[REDACTED_EMAIL_1]" in data["sanitized_text"]
    assert data["total_entities"] == 2


def test_sanitize_synthetic():
    payload = {
        "text": "Client Maria CPF 123.456.789-00 requested transfer",
        "redact_type": "synthetic",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "123.456.789-00" not in data["sanitized_text"]
    assert data["total_entities"] >= 1


def test_rfc7807_empty_text():
    payload = {"text": "   ", "redact_type": "placeholder"}
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 400
    assert response.headers["content-type"] == "application/problem+json"
    data = response.json()
    assert data["status"] == 400
    assert "Bad Request" in data["title"]


def test_mock_llm_completion():
    # Reset mock state
    client.post("/mock-llm/reset")

    payload = {
        "messages": [{"role": "user", "content": "Test prompt"}],
        "model": "gpt-4o",
    }
    response = client.post("/mock-llm/v1/chat/completions", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "usage" in data
    assert data["usage"]["total_tokens"] > 0

    # Verify state recording
    state_res = client.get("/mock-llm/last-request")
    state_data = state_res.json()
    assert state_data["payload"]["messages"][0]["content"] == "Test prompt"
