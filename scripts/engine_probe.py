#!/usr/bin/env python3
"""
Engine Probe Script — KAG-T01 Baseline Reproduction
===================================================
Captures the "before" state of detect_and_sanitize against fixed test inputs:
- 11-digit order number (False Positive: flagged as CPF due to raw 11-digit regex)
- Unformatted phone number (Misclassified as CPF instead of PHONE)
- Invalid CPF strings (False Positive: checksum validator never called in engine)
- Bank Account "Agência 1234 Conta 56789-0" (False Negative: regex pattern fails to match)

Usage:
    python scripts/engine_probe.py
"""

import os
import sys

# Ensure UTF-8 output in Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure pii-sanitizer root is on python path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PII_SANITIZER_ROOT = os.path.join(WORKSPACE_ROOT, "pii-sanitizer")
if PII_SANITIZER_ROOT not in sys.path:
    sys.path.insert(0, PII_SANITIZER_ROOT)

from app.pii_engine import detect_and_sanitize
from app.schemas import RedactType


PROBE_CASES = [
    {
        "category": "Order Number (11 digits)",
        "input": "Pedido 12345678901 faturado com sucesso",
        "expected_defect": "[F-01] Raw 11-digit regex matches without checksum; falsely detected as CPF.",
    },
    {
        "category": "Phone Numbers (formatted and unformatted 11-digit)",
        "input": "Ligue para (11) 98765-4321 ou envie mensagem para 11987654321",
        "expected_defect": "[F-01] Unformatted 11-digit phone is captured as CPF before or instead of PHONE.",
    },
    {
        "category": "Invalid CPF (failing checksum validation)",
        "input": "CPFs invalidos: 123.456.789-00 e 111.111.111-11 e raw 12345678900",
        "expected_defect": "[F-01] All invalid CPFs detected as CPF because validate_cpf_digits is never called.",
    },
    {
        "category": "Bank Account (standard Brazilian format)",
        "input": "Favor transferir para Agência 1234 Conta 56789-0",
        "expected_defect": "[F-03] Bank account regex fails to capture Agência + Conta compound pattern (0 entities).",
    },
]


def run_probe():
    print("=" * 80)
    print("KAG-T01: PII Engine Baseline Probe (Before Fixes)")
    print("=" * 80)

    for i, case in enumerate(PROBE_CASES, 1):
        print(f"\n--- Case {i}: {case['category']} ---")
        print(f"Input: {case['input']}")
        print(f"Known Defect Context: {case['expected_defect']}")

        result = detect_and_sanitize(case["input"], redact_type=RedactType.PLACEHOLDER)

        print(f"Sanitized Text: {result.sanitized_text}")
        print(f"Total Entities Detected: {result.total_entities}")
        if result.pii_detected:
            for entity in result.pii_detected:
                print(
                    f"  - Type: {entity.type} | Original: '{entity.original}' | "
                    f"Replacement: '{entity.replacement}' | Span: [{entity.start}:{entity.end}] | "
                    f"Checksum Valid: {entity.checksum_valid}"
                )
        else:
            print("  - (None detected)")

    print("\n" + "=" * 80)
    print("Probe Complete — Baseline State Successfully Captured.")
    print("=" * 80)


if __name__ == "__main__":
    run_probe()
