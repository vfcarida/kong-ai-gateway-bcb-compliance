"""
Pytest Suite — Reversible Tokenization Vault & Re-Identification (FEAT-05)
==========================================================================
Tests two-way de-identification on ingress and re-identification on egress
for authorized banking services, validating session-level isolation,
placeholder/synthetic restoration, and RFC 7807 error boundaries.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure app package is importable from pii-sanitizer root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.token_vault import TokenVault

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    """Resets mock state and token vault before each test."""
    client.post("/mock-llm/reset")
    yield


def test_reversible_vault_placeholder_mode():
    """Verifies round-trip de-identification and re-identification with placeholder tokens."""
    session_id = "sess-banking-placeholder-01"
    original_text = (
        "Favor aprovar o PIX de R$ 3.450,00 para o CPF 123.456.789-09 "
        "e conta corrente 56789-0 agência 1234."
    )

    # 1. Ingress Sanitization
    res_sanitize = client.post(
        "/sanitize",
        json={
            "text": original_text,
            "redact_type": "placeholder",
            "session_id": session_id,
        },
    )
    assert res_sanitize.status_code == 200
    sanitized_data = res_sanitize.json()
    sanitized_text = sanitized_data["sanitized_text"]
    assert "123.456.789-09" not in sanitized_text
    assert "[REDACTED_CPF_1]" in sanitized_text

    # 2. Egress Re-identification
    res_reid = client.post(
        "/re-identify",
        json={
            "text": sanitized_text,
            "session_id": session_id,
        },
    )
    assert res_reid.status_code == 200
    reid_data = res_reid.json()
    assert reid_data["session_id"] == session_id
    assert reid_data["restored_entities"] >= 3
    assert reid_data["reidentified_text"] == original_text


def test_reversible_vault_synthetic_mode():
    """Verifies round-trip de-identification and re-identification with synthetic pseudonymization."""
    session_id = "sess-banking-synthetic-02"
    original_text = "O cliente Carlos Silva portador do CPF 123.456.789-09 solicitou saldo."

    # 1. Ingress Sanitization
    res_sanitize = client.post(
        "/sanitize",
        json={
            "text": original_text,
            "redact_type": "synthetic",
            "session_id": session_id,
        },
    )
    assert res_sanitize.status_code == 200
    sanitized_data = res_sanitize.json()
    sanitized_text = sanitized_data["sanitized_text"]
    assert "123.456.789-09" not in sanitized_text

    # 2. Egress Re-identification
    res_reid = client.post(
        "/re-identify",
        json={
            "text": sanitized_text,
            "session_id": session_id,
        },
    )
    assert res_reid.status_code == 200
    reid_data = res_reid.json()
    assert "123.456.789-09" in reid_data["reidentified_text"]
    assert "Carlos Silva" in reid_data["reidentified_text"]
    assert reid_data["reidentified_text"] == original_text


def test_llm_completion_echo_reidentification():
    """Simulates an LLM assistant completion referencing synthetic entities being re-identified."""
    session_id = "sess-llm-dialogue-03"

    # Step 1: User prompt sanitized
    user_prompt = "Mariana Oliveira portadora do CPF 123.456.789-09 deseja extrato bancario."
    res1 = client.post(
        "/sanitize",
        json={
            "text": user_prompt,
            "redact_type": "synthetic",
            "session_id": session_id,
        },
    )
    assert res1.status_code == 200
    entities = res1.json()["pii_detected"]
    synth_name = next(e["replacement"] for e in entities if e["type"] == "NAME")
    synth_cpf = next(e["replacement"] for e in entities if e["type"] == "CPF")

    # Step 2: LLM generates completion using the synthetic entities
    llm_completion = f"Atendimento realizado com sucesso para {synth_name} (CPF {synth_cpf}). Saldo enviado."

    # Step 3: Banking egress pipeline re-identifies the completion
    res2 = client.post(
        "/re-identify",
        json={
            "text": llm_completion,
            "session_id": session_id,
        },
    )
    assert res2.status_code == 200
    reid_completion = res2.json()["reidentified_text"]
    assert "Mariana Oliveira" in reid_completion
    assert "123.456.789-09" in reid_completion
    assert synth_name not in reid_completion
    assert synth_cpf not in reid_completion


def test_reidentify_session_isolation():
    """Verifies that separate sessions maintain distinct mappings and cannot re-identify across boundaries."""
    client.post(
        "/sanitize",
        json={
            "text": "CPF 123.456.789-09",
            "redact_type": "placeholder",
            "session_id": "session-ALPHA",
        },
    )

    # Calling with session-BETA which has not registered this entity
    res = client.post(
        "/re-identify",
        json={
            "text": "Payload com [REDACTED_CPF_1]",
            "session_id": "session-BETA",
        },
    )
    assert res.status_code == 200
    data = res.json()
    # No replacement should occur for unassociated session
    assert data["reidentified_text"] == "Payload com [REDACTED_CPF_1]"
    assert data["restored_entities"] == 0


def test_reidentify_empty_text_returns_rfc7807():
    """Empty text must trigger RFC 7807 400 Problem Details."""
    res = client.post(
        "/re-identify",
        json={
            "text": "   ",
            "session_id": "any-session",
        },
    )
    assert res.status_code == 400
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 400
    assert "Bad Request" in body["title"]


def test_token_vault_lru_eviction():
    """Tests LRU capacity eviction in TokenVault."""
    vault = TokenVault(max_sessions=3)
    vault.record_entity("s1", "CPF:1", "111", "[REP1]")
    vault.record_entity("s2", "CPF:2", "222", "[REP2]")
    vault.record_entity("s3", "CPF:3", "333", "[REP3]")
    assert vault.active_sessions_count == 3

    # Adding a 4th session should evict s1 (the oldest unaccessed)
    vault.record_entity("s4", "CPF:4", "444", "[REP4]")
    assert vault.active_sessions_count == 3
    assert vault.get_session("s1") is None
    assert vault.get_session("s4") is not None


def test_reversible_vault_pix_and_rg():
    """Tests round-trip sanitization and re-identification for PIX_KEY (EVP) and RG."""
    session_id = "sess-pix-rg-vault-01"
    evp = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
    rg = "23.456.789-X"
    original = f"Transferir para chave pix {evp} do titular com RG {rg}."

    # 1. Sanitize with synthetic
    res_san = client.post(
        "/sanitize",
        json={"text": original, "redact_type": "synthetic", "session_id": session_id},
    )
    assert res_san.status_code == 200
    san_text = res_san.json()["sanitized_text"]
    assert evp not in san_text
    assert rg not in san_text

    # 2. Re-identify
    res_reid = client.post(
        "/re-identify",
        json={"text": san_text, "session_id": session_id},
    )
    assert res_reid.status_code == 200
    reid_data = res_reid.json()
    assert reid_data["restored_entities"] == 2
    assert evp in reid_data["reidentified_text"]
    assert rg in reid_data["reidentified_text"]
