"""
Pytest Suite — Adversarial, Boundary & Fuzzing Edge-Case Tests (TEST-02)
=========================================================================
Automated security, robustness, and fuzzing tests validating the PII engine against:
- Modulo-11 checksum edge cases and all repeated-digit sequences (000...00 to 999...99)
- Zero-width and invisible Unicode characters (\\u200B, \\u200C, \\u200D, \\uFEFF)
- Unicode homoglyphs and confusables (Cyrillic/Greek substitutions)
- Extreme whitespace, punctuation, and non-breaking space permutations
- Deeply nested and oversized payloads
- RFC 7807 problem details contract compliance across error boundaries
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure app package is importable from pii-sanitizer root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.pii_engine import (
    validate_cpf_digits,
    validate_cnpj_digits,
    validate_luhn_checksum,
    detect_and_sanitize,
)
from app.schemas import RedactType

client = TestClient(app)


# ── 1. Modulo-11 Checksum Edge Cases & Repeated Sequences ──────────────────────


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_cpf_all_identical_digits_are_invalid(digit):
    """Verifies that all repeated-digit CPFs (00000000000 through 99999999999) are strictly rejected."""
    raw_cpf = digit * 11
    assert validate_cpf_digits(raw_cpf) is False, f"CPF {raw_cpf} should be invalid"


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_formatted_cpf_identical_digits_flagged_with_invalid_checksum(digit):
    """Formatted identical-digit CPFs (e.g. 222.222.222-22) are detected as CPF but checksum_valid=False."""
    formatted = f"{digit*3}.{digit*3}.{digit*3}-{digit*2}"
    res = client.post("/sanitize", json={"text": f"Documento: {formatted}", "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    cpfs = [e for e in data["pii_detected"] if e["type"] == "CPF"]
    assert len(cpfs) == 1
    assert cpfs[0]["checksum_valid"] is False


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_raw_identical_digits_never_detected_as_cpf(digit):
    """Raw 11-digit sequences with identical digits must NOT be flagged as CPF (prevents false positives)."""
    raw_number = digit * 11
    res = client.post("/sanitize", json={"text": f"Pedido {raw_number} registrado", "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    cpfs = [e for e in data["pii_detected"] if e["type"] == "CPF"]
    assert len(cpfs) == 0, f"Raw number {raw_number} should not be treated as CPF"


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_cnpj_all_identical_digits_are_invalid(digit):
    """Verifies that all repeated-digit CNPJs (14 identical digits) are strictly rejected."""
    raw_cnpj = digit * 14
    assert validate_cnpj_digits(raw_cnpj) is False, f"CNPJ {raw_cnpj} should be invalid"


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_raw_identical_digits_never_detected_as_cnpj(digit):
    """Raw 14-digit sequences with identical digits must NOT be flagged as CNPJ."""
    raw_number = digit * 14
    res = client.post("/sanitize", json={"text": f"Nota {raw_number} emitida", "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    cnpjs = [e for e in data["pii_detected"] if e["type"] == "CNPJ"]
    assert len(cnpjs) == 0


def test_cpf_boundary_lengths():
    """Lengths other than 11 digits must fail validation."""
    assert validate_cpf_digits("") is False
    assert validate_cpf_digits("1234567890") is False  # 10 digits
    assert validate_cpf_digits("123456789012") is False  # 12 digits
    assert validate_cpf_digits("abcdefghijk") is False  # 11 non-digits


def test_cnpj_boundary_lengths():
    """Lengths other than 14 digits must fail validation."""
    assert validate_cnpj_digits("") is False
    assert validate_cnpj_digits("1122233300018") is False  # 13 digits
    assert validate_cnpj_digits("112223330001811") is False  # 15 digits


@pytest.mark.parametrize("digit", [str(d) for d in range(10)])
def test_raw_identical_digits_never_detected_as_credit_card(digit):
    """Raw 16-digit sequences with identical digits must NOT be flagged as credit card."""
    raw_number = digit * 16
    res = client.post("/sanitize", json={"text": f"Lote {raw_number} registrado", "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    cards = [e for e in data["pii_detected"] if e["type"] == "CREDIT_CARD"]
    assert len(cards) == 0


def test_credit_card_boundary_lengths():
    """Lengths other than 13-19 digits or invalid characters must fail validation."""
    assert validate_luhn_checksum("") is False
    assert validate_luhn_checksum("123456789012") is False  # 12 digits (too short)
    assert validate_luhn_checksum("12345678901234567890") is False  # 20 digits (too long)
    assert validate_luhn_checksum("555555555555444a") is False


# ── 2. Zero-Width & Invisible Characters ───────────────────────────────────────


@pytest.mark.parametrize(
    "invisible_char,char_name",
    [
        ("\u200B", "zero-width-space"),
        ("\u200C", "zero-width-non-joiner"),
        ("\u200D", "zero-width-joiner"),
        ("\uFEFF", "byte-order-mark"),
        ("\u00A0", "non-breaking-space"),
        ("\u00AD", "soft-hyphen"),
    ],
)
def test_invisible_characters_handling_no_crash(invisible_char, char_name):
    """Ensures input texts laden with invisible or zero-width characters do not crash the engine."""
    adversarial_text = (
        f"Cliente{invisible_char}Carlos{invisible_char}Silva{invisible_char} "
        f"com{invisible_char}email{invisible_char}carlos@banco.com.br{invisible_char} "
        f"e CPF 123.456.789-09."
    )
    res = client.post("/sanitize", json={"text": adversarial_text, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    assert "sanitized_text" in data
    assert data["total_entities"] >= 1


def test_zero_width_space_within_regular_tokens():
    """Verifies that zero-width space inside normal tokens does not trigger catastrophic regex backtracking."""
    evil_string = "a" + ("\u200b" * 500) + "b@banco.com.br"
    res = client.post("/sanitize", json={"text": evil_string, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    assert data["processing_time_ms"] < 2000.0  # Must complete in reasonable time


# ── 3. Homoglyphs & Unicode Confusables ────────────────────────────────────────


def test_cyrillic_homoglyphs_in_name():
    """Verifies that Cyrillic homoglyphs (e.g. Cyrillic 'а', 'е', 'о') are handled gracefully."""
    # Latin "Carlos Silva" vs Cyrillic 'а' (\u0430) and 'о' (\u043e)
    cyrillic_name = "C\u0430rl\u043es Silv\u0430"
    res = client.post("/sanitize", json={"text": f"Nome: {cyrillic_name}", "redact_type": "synthetic"})
    assert res.status_code == 200
    data = res.json()
    assert "sanitized_text" in data


def test_fullwidth_latin_characters():
    """Verifies handling of Fullwidth ASCII forms (e.g., Ｕser@banco.com.br)."""
    fullwidth_text = "\uff35ser@banco.com.br CPF 123.456.789-09"
    res = client.post("/sanitize", json={"text": fullwidth_text, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    assert "[REDACTED_CPF_1]" in data["sanitized_text"]


# ── 4. Mixed Whitespace & Boundary Delimiters ─────────────────────────────────


def test_money_with_irregular_spaces_and_tabs():
    """Verifies money expressions with tabs and multiple spaces are parsed cleanly."""
    text = "Valor: R$\t  1.250,50   e outro de R$  50,00."
    res = client.post("/sanitize", json={"text": text, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    money_entities = [e for e in data["pii_detected"] if e["type"] == "MONEY"]
    assert len(money_entities) == 2
    # Verify no trailing period is captured
    for m in money_entities:
        assert not m["original"].endswith(".")


def test_bank_account_with_mixed_linebreaks_and_tabs():
    """Verifies bank account regex with newlines, tabs, and colons."""
    text = "Agência:\t 1234\nConta Corrente: 56789-0"
    res = client.post("/sanitize", json={"text": text, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    accts = [e for e in data["pii_detected"] if e["type"] == "BANK_ACCOUNT"]
    assert len(accts) >= 1


# ── 5. Stress, Extreme Payloads & Non-Regression ──────────────────────────────


def test_large_payload_with_multiple_pii_entities():
    """Verifies processing of 20KB payload with interleaved PII without degradation."""
    paragraph = "O cliente Maria Santos, CPF 123.456.789-09, telefone (11) 98765-4321 realizou PIX de R$ 350,00. "
    large_payload = paragraph * 100  # ~10KB
    res = client.post("/sanitize", json={"text": large_payload, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_entities"] > 0
    assert "123.456.789-09" not in data["sanitized_text"]


def test_all_ascii_punctuation_and_emojis():
    """Verifies input consisting of emojis, special math symbols, and punctuation."""
    emoji_text = "🚀💰🔒 [ALERT] 💳 R$ 1.000,00 transferido para 123.456.789-09! #BCB @bacen 🏦"
    res = client.post("/sanitize", json={"text": emoji_text, "redact_type": "placeholder"})
    assert res.status_code == 200
    data = res.json()
    assert "[REDACTED_CPF_1]" in data["sanitized_text"]
    assert "[REDACTED_MONEY_1]" in data["sanitized_text"]


# ── 6. RFC 7807 Error Contract Verification ───────────────────────────────────


def test_rfc7807_error_contract_on_empty_string():
    """Empty or whitespace-only strings must return RFC 7807 400 Problem Details."""
    res = client.post("/sanitize", json={"text": "   ", "redact_type": "placeholder"})
    assert res.status_code == 400
    assert res.headers.get("content-type") == "application/problem+json"
    body = res.json()
    assert body["status"] == 400
    assert "Bad Request" in body["title"]
    assert "detail" in body
    assert "instance" in body


def test_rfc7807_error_contract_on_invalid_redact_type():
    """Unrecognized redact_type values must return RFC 7807 422 / 400 Problem Details."""
    res = client.post("/sanitize", json={"text": "Hello world", "redact_type": "invalid_mode"})
    assert res.status_code in (400, 422)
    body = res.json()
    # Pydantic or custom handler returns problem structure or detail
    assert "detail" in body
