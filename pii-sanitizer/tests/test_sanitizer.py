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

