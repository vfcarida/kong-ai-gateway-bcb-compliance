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
from app.pii_engine import validate_cpf_digits, validate_cnpj_digits, validate_luhn_checksum

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "BCB" in data["compliance"]


def test_prometheus_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    content = response.text
    assert "pii_sanitizer_requests_total" in content
    assert "pii_sanitizer_entities_detected_total" in content
    assert "pii_sanitizer_processing_seconds" in content
    assert "pii_vault_active_sessions" in content


def test_validate_cpf_checksums():
    assert validate_cpf_digits("12345678909") is True
    assert validate_cpf_digits("11111111111") is False  # All identical digits
    assert validate_cpf_digits("12345678900") is False  # Invalid check digits


def test_validate_cnpj_checksums():
    assert validate_cnpj_digits("11222333000181") is True
    assert validate_cnpj_digits("00000000000000") is False


def test_validate_luhn_checksums():
    assert validate_luhn_checksum("5555555555554444") is True
    assert validate_luhn_checksum("5555555555554445") is False
    assert validate_luhn_checksum("0000000000000000") is False
    assert validate_luhn_checksum("4532abcd1234efgh") is False
    assert validate_luhn_checksum("1234567890") is False


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


def test_sanitize_credit_card_placeholder():
    payload = {
        "text": "Favor estornar compra no cartao 4532 1234 5678 9010 urgente",
        "redact_type": "placeholder",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "[REDACTED_CREDIT_CARD_1]" in data["sanitized_text"]
    assert any(e["type"] == "CREDIT_CARD" for e in data["pii_detected"])


def test_sanitize_credit_card_synthetic():
    payload = {
        "text": "Cartao 5555555555554444 cadastrado",
        "redact_type": "synthetic",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    card_entity = next(e for e in data["pii_detected"] if e["type"] == "CREDIT_CARD")
    assert card_entity["checksum_valid"] is True
    import re
    digits = re.sub(r"\D", "", card_entity["replacement"])
    assert validate_luhn_checksum(digits) is True


def test_sanitize_pix_key_placeholder():
    payload = {
        "text": "Minha chave pix aleatoria e 123e4567-e89b-12d3-a456-426614174000 para receber",
        "redact_type": "placeholder",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "[REDACTED_PIX_KEY_1]" in data["sanitized_text"]
    assert any(e["type"] == "PIX_KEY" for e in data["pii_detected"])


def test_sanitize_pix_key_synthetic():
    evp = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
    payload = {
        "text": f"Pagar para chave pix {evp} agora",
        "redact_type": "synthetic",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    pix_entity = next(e for e in data["pii_detected"] if e["type"] == "PIX_KEY")
    assert pix_entity["original"] == evp
    assert pix_entity["replacement"] != evp
    import re
    assert re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", pix_entity["replacement"])


def test_sanitize_rg_placeholder_and_synthetic():
    payload_ph = {
        "text": "Titular documento RG 12.345.678-9 SSP/SP autenticado",
        "redact_type": "placeholder",
    }
    res_ph = client.post("/sanitize", json=payload_ph)
    assert res_ph.status_code == 200
    assert "[REDACTED_RG_1]" in res_ph.json()["sanitized_text"]

    payload_synth = {
        "text": "Documento RG 12.345.678-X apresentado no balcao",
        "redact_type": "synthetic",
    }
    res_synth = client.post("/sanitize", json=payload_synth)
    assert res_synth.status_code == 200
    data_synth = res_synth.json()
    rg_entity = next(e for e in data_synth["pii_detected"] if e["type"] == "RG")
    import re
    assert re.match(r"^\d{2}\.\d{3}\.\d{3}-[\dXx]$", rg_entity["replacement"])


def test_synthetic_consistency_repeated_cpf_in_single_prompt():
    """Verifies identical PII entities receive the identical synthetic value within the same prompt."""
    payload = {
        "text": (
            "Primeira mencao: CPF 123.456.789-09 do cliente. "
            "Segunda mencao: confirmar transferencia para o mesmo titular do CPF 123.456.789-09."
        ),
        "redact_type": "synthetic",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_entities"] == 2

    # Both occurrences of the same CPF must be replaced with the exact same synthetic replacement
    entity1 = data["pii_detected"][0]
    entity2 = data["pii_detected"][1]
    assert entity1["replacement"] == entity2["replacement"]
    # The replacement must occur twice in the sanitized text
    assert data["sanitized_text"].count(entity1["replacement"]) == 2


def test_synthetic_consistency_format_awareness():
    """Verifies that formatted and unformatted representations share the same synthetic identity."""
    payload = {
        "text": "Formatado: 123.456.789-09. Sem pontuacao: 12345678909.",
        "redact_type": "synthetic",
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_entities"] == 2

    e_formatted = next(e for e in data["pii_detected"] if "." in e["original"])
    e_raw = next(e for e in data["pii_detected"] if "." not in e["original"])

    # Raw digits stripped from both replacements must be strictly identical
    assert e_formatted["replacement"].replace(".", "").replace("-", "") == e_raw["replacement"]
    assert "." in e_formatted["replacement"]
    assert "." not in e_raw["replacement"]


def test_synthetic_consistency_session_id():
    """Verifies that passing session_id preserves synthetic identities across sequential API calls."""
    client.post("/mock-llm/reset")

    session_id = "sess-compliance-audit-42"
    payload1 = {
        "text": "Turno 1: O cliente cadastrado possui o CPF 123.456.789-09.",
        "redact_type": "synthetic",
        "session_id": session_id,
    }
    res1 = client.post("/sanitize", json=payload1)
    assert res1.status_code == 200
    data1 = res1.json()
    synth_cpf_1 = data1["pii_detected"][0]["replacement"]

    payload2 = {
        "text": "Turno 2: Por favor detalhe as operacoes do CPF 123.456.789-09.",
        "redact_type": "synthetic",
        "session_id": session_id,
    }
    res2 = client.post("/sanitize", json=payload2)
    assert res2.status_code == 200
    data2 = res2.json()
    synth_cpf_2 = data2["pii_detected"][0]["replacement"]

    # Must preserve identity across sessions
    assert synth_cpf_1 == synth_cpf_2


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


def test_mock_llm_disabled_guard(monkeypatch):
    """Verifies that setting ENABLE_MOCK_LLM=false blocks mock LLM routes with RFC 7807 404."""
    monkeypatch.setenv("ENABLE_MOCK_LLM", "false")

    # POST completions
    payload = {"messages": [{"role": "user", "content": "Confidential prompt"}]}
    res = client.post("/mock-llm/v1/chat/completions", json=payload)
    assert res.status_code == 404
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 404
    assert "Not Found" in body["title"]
    assert "disabled" in body["detail"]

    # GET last-request
    res_last = client.get("/mock-llm/last-request")
    assert res_last.status_code == 404
    assert res_last.headers.get("content-type") == "application/problem+json"

    # POST reset
    res_reset = client.post("/mock-llm/reset")
    assert res_reset.status_code == 404
    assert res_reset.headers.get("content-type") == "application/problem+json"

    # Root endpoint should not list mock_llm endpoints
    root_res = client.get("/")
    assert "mock_llm" not in root_res.json()["endpoints"]


# ── Labelled Verification Table (KAG-T03: Checksum-Gated Detection & Regex Fixes) ──

LABELLED_DETECTION_CASES = [
    # (label, input_text, expected_type, expected_checksum_valid, should_detect)
    ("valid_formatted_cpf", "CPF do cliente: 123.456.789-09", "CPF", True, True),
    ("invalid_formatted_cpf", "CPF com digito invalido: 123.456.789-00", "CPF", False, True),
    ("all_identical_formatted_cpf", "CPF invalido: 000.000.000-00", "CPF", False, True),
    ("valid_raw_cpf", "Documento 12345678909 cadastrado", "CPF", True, True),
    ("invalid_raw_11_digits_order_number", "Pedido 12345678901 faturado com sucesso", "CPF", None, False),
    ("invalid_raw_11_digits_fake_cpf", "Identificador 12345678900 sem pontos", "CPF", None, False),
    ("valid_formatted_cnpj", "Empresa CNPJ 11.222.333/0001-81 ativa", "CNPJ", True, True),
    ("invalid_formatted_cnpj", "CNPJ irregular 00.000.000/0000-00", "CNPJ", False, True),
    ("valid_raw_cnpj", "Registro CNPJ 11222333000181 corporativo", "CNPJ", True, True),
    ("invalid_raw_14_digits", "Contrato 12345678901234 arquivado", "CNPJ", None, False),
    ("formatted_phone_mobile", "Contato (11) 99876-5432 disponivel", "PHONE", None, True),
    ("unformatted_phone_mobile", "Ligue para 11998765432 imediatamente", "PHONE", None, True),
    ("formatted_phone_landline", "Central (11) 3456-7890 comercial", "PHONE", None, True),
    ("unformatted_phone_landline", "Fixo 1134567890 suporte", "PHONE", None, True),
    ("bank_account_compound_standard", "Favor transferir para Agência 1234 Conta 56789-0", "BANK_ACCOUNT", None, True),
    ("bank_account_compound_punctuation", "Dados: Agência: 1234, Conta: 56789-0", "BANK_ACCOUNT", None, True),
    ("bank_account_compound_with_cc", "Transferencia Ag. 1234 C/C 56789-0 confirmada", "BANK_ACCOUNT", None, True),
    ("bank_account_compound_reverse", "Creditado em Conta 56789-0 Agência 1234 hoje", "BANK_ACCOUNT", None, True),
    ("money_trailing_period", "O saldo restante é R$ 150,00.", "MONEY", None, True),
    ("money_trailing_comma", "O total foi R$ 50, mas com desconto.", "MONEY", None, True),
    ("formatted_credit_card_valid", "Cartao final 5555-5555-5555-4444 ativo", "CREDIT_CARD", True, True),
    ("raw_credit_card_valid", "Transacao no cartao 5555555555554444 aprovada", "CREDIT_CARD", True, True),
    ("raw_16_digits_invalid_card", "Codigo de rastreamento 1234567890123456 do pedido", "CREDIT_CARD", None, False),
    ("pix_key_evp_uuid", "Chave aleatoria pix: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d para transferencia", "PIX_KEY", None, True),
    ("formatted_rg_standard", "Documento de identidade RG 12.345.678-9 emitido pela SSP", "RG", None, True),
    ("formatted_rg_digit_x", "Identidade RG 12.345.678-X apresentada", "RG", None, True),
]


@pytest.mark.parametrize(
    "label,input_text,expected_type,expected_checksum_valid,should_detect",
    LABELLED_DETECTION_CASES,
    ids=[c[0] for c in LABELLED_DETECTION_CASES],
)
def test_labelled_detection_table(label, input_text, expected_type, expected_checksum_valid, should_detect):
    payload = {"text": input_text, "redact_type": "placeholder"}
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()

    if not should_detect:
        # Assert the target type is NOT detected (e.g. order number must not be flagged as CPF)
        detected_of_type = [e for e in data["pii_detected"] if e["type"] == expected_type]
        assert len(detected_of_type) == 0, f"Unexpectedly detected {expected_type} in '{input_text}': {detected_of_type}"
    else:
        detected_of_type = [e for e in data["pii_detected"] if e["type"] == expected_type]
        assert len(detected_of_type) >= 1, f"Expected {expected_type} in '{input_text}', found: {data['pii_detected']}"
        entity = detected_of_type[0]
        assert entity["checksum_valid"] == expected_checksum_valid, (
            f"Case {label}: expected checksum_valid={expected_checksum_valid}, got {entity['checksum_valid']}"
        )

        # For MONEY, assert trailing punctuation is never part of original entity
        if expected_type == "MONEY":
            assert not entity["original"].endswith("."), f"Trailing period captured in MONEY: {entity['original']}"
            assert not entity["original"].endswith(","), f"Trailing comma captured in MONEY: {entity['original']}"

