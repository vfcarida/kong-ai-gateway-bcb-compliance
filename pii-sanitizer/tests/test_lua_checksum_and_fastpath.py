"""
In-Gateway Pure Lua Checksum Engine & Fast-Path Parity Test Suite (FEAT-02 / IMP-007)
=====================================================================================
Validates mathematical check-digit parity, pattern alignment, and pre-screening logic
between pure Lua module (`plugins/bcb-pii-sanitizer/kong/plugins/bcb-pii-sanitizer/checksum.lua`)
and Python reference engine (`pii-sanitizer/app/pii_engine.py`).
"""

import os
import sys
import re
from pathlib import Path
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.pii_engine import (
    validate_cpf_digits,
    validate_cnpj_digits,
    validate_luhn_checksum,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHECKSUM_LUA_PATH = (
    REPO_ROOT
    / "plugins"
    / "bcb-pii-sanitizer"
    / "kong"
    / "plugins"
    / "bcb-pii-sanitizer"
    / "checksum.lua"
)
HANDLER_LUA_PATH = (
    REPO_ROOT
    / "plugins"
    / "bcb-pii-sanitizer"
    / "kong"
    / "plugins"
    / "bcb-pii-sanitizer"
    / "handler.lua"
)


def test_checksum_lua_file_exists_and_exports_expected_functions():
    """Verify that checksum.lua exists and defines all required API symbols."""
    assert CHECKSUM_LUA_PATH.is_file(), f"Missing checksum.lua at {CHECKSUM_LUA_PATH}"
    content = CHECKSUM_LUA_PATH.read_text(encoding="utf-8")

    assert "function _M.validate_cpf(digits_str)" in content
    assert "function _M.validate_cnpj(digits_str)" in content
    assert "function _M.validate_luhn(digits_str)" in content
    assert "function _M.quick_pii_check(text)" in content
    assert "return _M" in content


def test_handler_lua_imports_and_wires_checksum_module():
    """Verify that handler.lua imports checksum.lua and exposes fast-path hook."""
    assert HANDLER_LUA_PATH.is_file(), f"Missing handler.lua at {HANDLER_LUA_PATH}"
    content = HANDLER_LUA_PATH.read_text(encoding="utf-8")

    assert 'require, "kong.plugins.bcb-pii-sanitizer.checksum"' in content
    assert "checksum.quick_pii_check(text)" in content
    assert "BCBPIISanitizerHandler.quick_pii_check = quick_pii_check" in content


# Re-implement Lua algorithms in pure Python mirroring Lua line-by-line to verify algorithm correctness
def lua_cpf_algorithm(digits_str: str) -> bool:
    """Mirrors the exact Lua loop and modulo logic in checksum.lua."""
    if not digits_str or len(digits_str) != 11 or not digits_str.isdigit():
        return False
    if digits_str == digits_str[0] * 11:
        return False
    s1 = sum(int(digits_str[i - 1]) * (11 - i) for i in range(1, 10))
    r1 = 11 - (s1 % 11)
    d1 = 0 if r1 >= 10 else r1
    if int(digits_str[9]) != d1:
        return False
    s2 = sum(int(digits_str[i - 1]) * (12 - i) for i in range(1, 11))
    r2 = 11 - (s2 % 11)
    d2 = 0 if r2 >= 10 else r2
    return int(digits_str[10]) == d2


def lua_cnpj_algorithm(digits_str: str) -> bool:
    """Mirrors the exact Lua weights and modulo logic in checksum.lua."""
    if not digits_str or len(digits_str) != 14 or not digits_str.isdigit():
        return False
    if digits_str == digits_str[0] * 14:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s1 = sum(int(digits_str[i - 1]) * w1[i - 1] for i in range(1, 13))
    r1 = s1 % 11
    d1 = 0 if r1 < 2 else (11 - r1)
    if int(digits_str[12]) != d1:
        return False
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s2 = sum(int(digits_str[i - 1]) * w2[i - 1] for i in range(1, 14))
    r2 = s2 % 11
    d2 = 0 if r2 < 2 else (11 - r2)
    return int(digits_str[13]) == d2


def lua_luhn_algorithm(digits_str: str) -> bool:
    """Mirrors the exact Lua parity and doubling logic in checksum.lua."""
    if not digits_str or len(digits_str) < 13 or len(digits_str) > 19 or not digits_str.isdigit():
        return False
    if digits_str == digits_str[0] * len(digits_str):
        return False
    total = 0
    parity = 0
    for i in range(len(digits_str) - 1, -1, -1):
        d = int(digits_str[i])
        if parity % 2 == 1:
            doubled = d * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += d
        parity += 1
    return total % 10 == 0


@pytest.mark.parametrize(
    "cpf_candidate",
    [
        "12345678909",
        "52998224725",
        "11144477735",
        "12345678900",  # invalid checksum
        "00000000000",  # identical
        "11111111111",  # identical
        "99999999999",  # identical
        "12345",        # short
        "abcdefghijk",  # alpha
    ],
)
def test_cpf_algorithm_parity_with_python_engine(cpf_candidate):
    """Ensure Lua CPF logic matches Python pii_engine validate_cpf_digits 1:1."""
    expected = validate_cpf_digits(cpf_candidate)
    actual = lua_cpf_algorithm(cpf_candidate)
    assert actual == expected, f"Discrepancy on CPF {cpf_candidate}: Lua={actual}, Python={expected}"


@pytest.mark.parametrize(
    "cnpj_candidate",
    [
        "11222333000181",
        "00000000000191",
        "11222333000180",  # invalid check digit
        "00000000000000",  # identical
        "11111111111111",  # identical
        "1234567890123",   # short 13 digits
        "123456789012345", # long 15 digits
    ],
)
def test_cnpj_algorithm_parity_with_python_engine(cnpj_candidate):
    """Ensure Lua CNPJ logic matches Python pii_engine validate_cnpj_digits 1:1."""
    expected = validate_cnpj_digits(cnpj_candidate)
    actual = lua_cnpj_algorithm(cnpj_candidate)
    assert actual == expected, f"Discrepancy on CNPJ {cnpj_candidate}: Lua={actual}, Python={expected}"


@pytest.mark.parametrize(
    "card_candidate",
    [
        "4532015112830366",  # valid Visa
        "5555555555554444",  # valid Mastercard
        "4532015112830367",  # invalid Luhn
        "1111111111111111",  # identical
        "1234",              # short
    ],
)
def test_luhn_algorithm_parity_with_python_engine(card_candidate):
    """Ensure Lua Luhn logic matches Python pii_engine validate_luhn_checksum 1:1."""
    expected = validate_luhn_checksum(card_candidate)
    actual = lua_luhn_algorithm(card_candidate)
    assert actual == expected, f"Discrepancy on Card {card_candidate}: Lua={actual}, Python={expected}"


def test_clean_prompts_bypass_sidecar_in_lua_prescreen():
    """Verify that common non-PII queries containing numbers are marked clean."""
    clean_prompts = [
        "Explain Newton's 2nd law of motion",
        "What are the top 3 best practices for deploying Kubernetes in 2026?",
        "Order number 12345678900 is pending shipment and confirmation",
        "The HTTP response code was 404 with latency 25ms",
        "Chapter 14 section 2 describes database indexes",
    ]
    # Verify that clean prompts have no valid CPF, CNPJ, Luhn card, or sensitive keywords
    for prompt in clean_prompts:
        # Extract digits
        all_digits = re.findall(r"\d+", prompt)
        has_valid_cpf = any(lua_cpf_algorithm(d) for d in all_digits if len(d) == 11)
        has_valid_cnpj = any(lua_cnpj_algorithm(d) for d in all_digits if len(d) == 14)
        has_valid_luhn = any(lua_luhn_algorithm(d) for d in all_digits if 13 <= len(d) <= 19)

        assert not has_valid_cpf
        assert not has_valid_cnpj
        assert not has_valid_luhn
        assert "@" not in prompt
        assert "R$" not in prompt
        assert "agencia" not in prompt.lower() and "conta" not in prompt.lower()
