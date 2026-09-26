"""
Pytest Suite — Batch Sanitization & Security Payload Guard (FEAT-08 & SEC-05)
=============================================================================
Tests high-throughput batch sanitization for RAG/vector chunks, cross-chunk
pseudonym consistency, RFC 7807 Problem Details error boundaries, and maximum
payload length protection against DoS/ReDoS vulnerabilities.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app, MAX_PII_TEXT_LENGTH, MAX_BATCH_ITEMS

client = TestClient(app)


def test_sanitize_batch_success():
    """Verifies batch processing of multiple text chunks with entity detection."""
    payload = {
        "items": [
            {"id": "chunk-1", "text": "Cliente João Silva com CPF 123.456.789-09"},
            {"id": "chunk-2", "text": "Empresa CNPJ 11.222.333/0001-81 confirmada"},
            {"id": "chunk-3", "text": "Texto limpo sem qualquer dado confidencial"},
        ],
        "redact_type": "placeholder",
    }
    res = client.post("/sanitize-batch", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_items"] == 3
    assert data["total_entities"] >= 2
    assert data["processing_time_ms"] > 0

    assert data["items"][0]["id"] == "chunk-1"
    assert "[REDACTED_CPF_1]" in data["items"][0]["sanitized_text"]

    assert data["items"][1]["id"] == "chunk-2"
    assert "[REDACTED_CNPJ_1]" in data["items"][1]["sanitized_text"]

    assert data["items"][2]["id"] == "chunk-3"
    assert data["items"][2]["sanitized_text"] == "Texto limpo sem qualquer dado confidencial"
    assert data["items"][2]["total_entities"] == 0


def test_sanitize_batch_synthetic_cross_chunk_consistency():
    """Verifies that identical entities occurring across different chunks share the same synthetic value."""
    payload = {
        "items": [
            {"id": "chunk-a", "text": "Titular CPF 123.456.789-09 abriu solicitacao"},
            {"id": "chunk-b", "text": "Transferencia aprovada para o mesmo CPF 123.456.789-09"},
        ],
        "redact_type": "synthetic",
        "session_id": "sess-batch-consistency-01",
    }
    res = client.post("/sanitize-batch", json=payload)
    assert res.status_code == 200
    data = res.json()

    rep_a = data["items"][0]["pii_detected"][0]["replacement"]
    rep_b = data["items"][1]["pii_detected"][0]["replacement"]
    assert rep_a == rep_b, f"Expected cross-chunk consistency: '{rep_a}' != '{rep_b}'"

    # Egress Re-identification check
    reid_res = client.post(
        "/re-identify",
        json={"text": f"Resultado: {rep_a}", "session_id": "sess-batch-consistency-01"},
    )
    assert reid_res.status_code == 200
    assert "123.456.789-09" in reid_res.json()["reidentified_text"]


def test_sanitize_batch_empty_items_returns_rfc7807_400():
    """Empty items array must return RFC 7807 400 Bad Request."""
    res = client.post("/sanitize-batch", json={"items": []})
    assert res.status_code == 400
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 400
    assert "Bad Request" in body["title"]


def test_sanitize_batch_item_with_empty_text_returns_rfc7807_400():
    """Item with empty text inside batch must trigger RFC 7807 400 Bad Request."""
    payload = {
        "items": [
            {"id": "1", "text": "Valid prompt"},
            {"id": "2", "text": "   "},
        ]
    }
    res = client.post("/sanitize-batch", json=payload)
    assert res.status_code == 400
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 400
    assert "empty text" in body["detail"]


def test_sanitize_payload_too_large_rfc7807_413(monkeypatch):
    """Payload exceeding MAX_PII_TEXT_LENGTH returns RFC 7807 413 Payload Too Large."""
    # Temporarily set max length to 50 for fast deterministic testing
    monkeypatch.setattr("app.main.MAX_PII_TEXT_LENGTH", 50)

    large_text = "A" * 51
    res = client.post("/sanitize", json={"text": large_text})
    assert res.status_code == 413
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 413
    assert body["title"] == "Payload Too Large"
    assert "50 characters" in body["detail"]


def test_sanitize_batch_items_limit_rfc7807_413(monkeypatch):
    """Batch exceeding MAX_BATCH_ITEMS returns RFC 7807 413 Payload Too Large."""
    monkeypatch.setattr("app.main.MAX_BATCH_ITEMS", 3)

    payload = {
        "items": [
            {"id": f"item-{i}", "text": f"Text chunk {i}"} for i in range(4)
        ]
    }
    res = client.post("/sanitize-batch", json=payload)
    assert res.status_code == 413
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 413
    assert body["title"] == "Payload Too Large"
    assert "3 items" in body["detail"]
