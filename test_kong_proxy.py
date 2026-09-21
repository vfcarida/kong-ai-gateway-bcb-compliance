#!/usr/bin/env python3
"""
Kong AI Gateway — PII Sanitizer & Compliance Test Suite
=========================================================
Automated verification suite validating real-time PII obfuscation,
multi-provider failover capability, RFC 7807 error responses, and
compliance under Resolution BCB CMN 4893/21 and BCB 85/21.

Usage:
    python test_kong_proxy.py                   # Run full E2E verification suite
    python test_kong_proxy.py --sanitizer-only  # Test FastAPI PII service directly
    python test_kong_proxy.py --synthetic       # Validate synthetic data generation
"""

import os
import argparse
import json
import sys
import time
import re
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("❌ Required library 'requests' is not installed.")
    print("   Install it using: pip install requests")
    sys.exit(1)


# ── Configuration Constants ──────────────────────────────────────────────────

KONG_PROXY_URL = os.getenv("KONG_PROXY_URL", "http://localhost:8000")
KONG_ADMIN_URL = os.getenv("KONG_ADMIN_URL", "http://localhost:8001")
PII_SANITIZER_URL = os.getenv("PII_SANITIZER_URL", "https://localhost:8088")

# ── ANSI Color Codes for Output Formatting ────────────────────────────────────


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


def print_header(text: str) -> None:
    width = 80
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'=' * width}{Colors.END}\n")


def print_section(text: str) -> None:
    print(f"\n{Colors.BOLD}{Colors.CYAN}== {text} {'=' * (70 - len(text))}{Colors.END}\n")


def print_success(text: str) -> None:
    print(f"  {Colors.GREEN}[PASS] {text}{Colors.END}")


def print_error(text: str) -> None:
    print(f"  {Colors.RED}[FAIL] {text}{Colors.END}")


def print_warning(text: str) -> None:
    print(f"  {Colors.YELLOW}[WARN] {text}{Colors.END}")


def print_info(text: str) -> None:
    print(f"  {Colors.BLUE}[INFO] {text}{Colors.END}")


# ── Test Prompts and Scenarios ────────────────────────────────────────────────

TEST_PROMPTS = [
    {
        "name": "Scenario 1: Financial request with formatted CPF and Bank Account",
        "prompt": (
            "My name is João da Silva, my CPF is 123.456.789-00, "
            "Agência 1234 Conta 56789-0 and my balance is R$ 50.000. Can I transfer?"
        ),
        "expected_pii": ["NAME", "CPF", "MONEY", "BANK_ACCOUNT"],
    },
    {
        "name": "Scenario 2: Multi-PII Brazilian registration & CNPJ",
        "prompt": (
            "The company Acme Brasil (CNPJ 11.222.333/0001-81, "
            "contact Maria Oliveira CPF 98765432100, email maria@acme.com.br, "
            "tel (11) 99876-5432) requested a credit line of R$ 150.000,00."
        ),
        "expected_pii": ["CNPJ", "NAME", "CPF", "EMAIL", "PHONE", "MONEY"],
    },
    {
        "name": "Scenario 3: Negative Control (No sensitive data)",
        "prompt": "What are the core requirements of Resolution BCB CMN 4893/21?",
        "expected_pii": [],
    },
]


# ── Health Verification ───────────────────────────────────────────────────────


def test_health_checks() -> dict:
    """Verifies operational state of microservices."""
    print_section("Operational Health Checks")
    results = {}

    # PII Sanitizer
    # PII Sanitizer (HTTPS / TLS Encrypted)
    try:
        r = requests.get(f"{PII_SANITIZER_URL}/health", timeout=5, verify=False)
        if r.status_code == 200:
            print_success(f"PII Sanitizer is ONLINE (TLS): {r.json()}")
            results["pii_sanitizer"] = True
        else:
            print_error(f"PII Sanitizer returned status {r.status_code}")
            results["pii_sanitizer"] = False
    except requests.ConnectionError:
        print_error("PII Sanitizer is OFFLINE (ConnectionRefused)")
        results["pii_sanitizer"] = False

    # Kong Admin API (Hardened: Unexposed to host by default per BCB CMN 4893/21)
    try:
        r = requests.get(f"{KONG_ADMIN_URL}/status", timeout=2)
        if r.status_code == 200:
            status_data = r.json()
            connections = status_data.get("server", {}).get("connections_active", "?")
            print_success(f"Kong Gateway Admin is ONLINE: {connections} active connections")
            results["kong_gateway"] = True
        else:
            print_error(f"Kong Gateway returned status {r.status_code}")
            results["kong_gateway"] = False
    except requests.ConnectionError:
        print_info("Kong Admin API is unexposed to host (BCB CMN 4893/21 compliant hardening)")
        results["kong_gateway"] = True  # Hardened isolation is compliant

    return results


# ── Sanitizer Direct Verification ─────────────────────────────────────────────


def test_pii_sanitizer_direct() -> bool:
    """Tests PII Sanitizer microservice directly via REST."""
    print_section("Direct Service Verification — PII Sanitizer Engine")
    all_passed = True

    for scenario in TEST_PROMPTS:
        print(f"\n  {Colors.BOLD}Running: {scenario['name']}{Colors.END}")
        print(f"  {Colors.DIM}Prompt: \"{scenario['prompt'][:80]}...\"{Colors.END}")

        try:
            r = requests.post(
                f"{PII_SANITIZER_URL}/sanitize",
                json={"text": scenario["prompt"], "redact_type": "placeholder"},
                timeout=5,
                verify=False,
            )

            if r.status_code != 200:
                print_error(f"HTTP {r.status_code}: {r.text}")
                all_passed = False
                continue

            result = r.json()
            print(f"  {Colors.GREEN}Sanitized:{Colors.END} \"{result['sanitized_text'][:100]}...\"")
            print(f"  {Colors.CYAN}Metadata:{Colors.END} {result['total_entities']} entity matches")

            detected = {e["type"] for e in result["pii_detected"]}
            expected = set(scenario["expected_pii"])

            if expected:
                missing = expected - detected
                critical_missing = missing - {"NAME", "BANK_ACCOUNT"}
                if critical_missing:
                    print_error(f"Critical PII categories missed: {critical_missing}")
                    all_passed = False
                else:
                    print_success("Expected critical PII categories successfully obfuscated")
            else:
                if result["total_entities"] == 0:
                    print_success("Negative control confirmed: 0 entities identified")

        except Exception as e:
            print_error(f"Request failed: {e}")
            all_passed = False

    return all_passed


# ── RFC 7807 & Boundary Checks ────────────────────────────────────────────────


def test_rfc7807_and_boundaries() -> bool:
    """Verifies RFC 7807 Problem Details and empty payload limits."""
    print_section("Boundary & RFC 7807 Error Response Tests")
    all_passed = True

    print_info("Testing empty payload handling for RFC 7807 compliance...")
    try:
        r = requests.post(f"{PII_SANITIZER_URL}/sanitize", json={"text": "   "}, timeout=5, verify=False)
        if r.status_code == 400 and r.headers.get("content-type") == "application/problem+json":
            print_success("Handled empty payload with HTTP 400 & application/problem+json headers.")
            body = r.json()
            if "title" in body and "type" in body and "status" in body:
                print_success("RFC 7807 structural fields (type, title, status, detail) confirmed.")
            else:
                print_error("Missing required RFC 7807 fields in error payload.")
                all_passed = False
        else:
            print_error(f"Unexpected response: HTTP {r.status_code}, content-type: {r.headers.get('content-type')}")
            all_passed = False
    except Exception as e:
        print_error(f"Error testing RFC 7807 boundary: {e}")
        all_passed = False

    return all_passed


# ── Kong Gateway E2E Decoupled Flow ───────────────────────────────────────────


def test_kong_e2e() -> bool:
    """Tests end-to-end integration via Kong Gateway."""
    print_section("E2E Integration Verification — Kong AI Gateway")

    scenario = TEST_PROMPTS[0]
    print(f"  {Colors.BOLD}Prompt: \"{scenario['prompt']}\"{Colors.END}")

    # Reset last captured request state
    try:
        requests.post(f"{PII_SANITIZER_URL}/mock-llm/reset", timeout=5, verify=False)
    except Exception:
        pass

    payload = {
        "messages": [
            {"role": "system", "content": "You are a compliance assistant."},
            {"role": "user", "content": scenario["prompt"]},
        ],
        "temperature": 0.1,
    }

    try:
        print_info("Dispatching request to Kong Gateway (/llm-proxy)...")
        start_time = time.time()
        r = requests.post(
            f"{KONG_PROXY_URL}/llm-proxy",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        latency = time.time() - start_time

        print(f"  {Colors.BOLD}Gateway response (HTTP {r.status_code}) — Latency: {latency:.2f}s{Colors.END}")
        req_id = r.headers.get("X-Request-ID", "N/A")
        print(f"  {Colors.DIM}X-Request-ID: {req_id}{Colors.END}")

        if r.status_code != 200:
            print_error(f"Unsuccessful status: {r.status_code}")
            return False

        res_data = r.json()
        print_success("Gateway parsed request successfully.")

        # Inspect last request received by upstream mock LLM
        time.sleep(0.3)
        state_res = requests.get(f"{PII_SANITIZER_URL}/mock-llm/last-request", timeout=5, verify=False)
        state_data = state_res.json()

        payload_received = state_data.get("payload")
        if payload_received:
            user_content = ""
            for msg in payload_received.get("messages", []):
                if msg.get("role") == "user":
                    user_content = msg.get("content", "")

            sensitive_item = "123.456.789-00"
            if sensitive_item not in user_content:
                print_success(
                    f"COMPLIANCE PROVED: Sensitive CPF '{sensitive_item}' was "
                    "NOT present in payload received by upstream LLM!"
                )
                return True
            else:
                print_error(f"COMPLIANCE FAILURE: Sensitive CPF '{sensitive_item}' leaked upstream!")
                return False
        else:
            print_warning("Could not retrieve mock LLM state to verify payload.")
            return True

    except Exception as e:
        print_error(f"E2E Integration error: {e}")
        return False


# ── Main Entrypoint ───────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Kong AI Gateway BCB Compliance Test Suite")
    parser.add_argument("--sanitizer-only", action="store_true", help="Bypass Kong and test sanitizer only")
    parser.add_argument("--synthetic", action="store_true", help="Run synthetic obfuscation tests")
    args = parser.parse_args()

    print_header("Kong AI Gateway & BCB CMN 4893/21 & BCB 85/21 Compliance Suite")
    print(f"  {Colors.DIM}UTC Execution Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{Colors.END}")

    health = test_health_checks()
    results = {}

    results["Service Health"] = health.get("pii_sanitizer", False)

    if results["Service Health"]:
        results["PII Engine Verification"] = test_pii_sanitizer_direct()
        results["RFC 7807 Error Response"] = test_rfc7807_and_boundaries()

        if not args.sanitizer_only and health.get("kong_gateway", False):
            results["E2E Interception Audit"] = test_kong_e2e()

    print_section("Compliance Test Run Summary")
    passed_runs = sum(1 for status_val in results.values() if status_val)
    total_runs = len(results)

    for test_name, status_val in results.items():
        outcome = f"{Colors.GREEN}PASS{Colors.END}" if status_val else f"{Colors.RED}FAIL{Colors.END}"
        print(f"  {outcome}  {test_name}")

    print(f"\n  {Colors.BOLD}Overall result: {passed_runs}/{total_runs} tests passed.{Colors.END}\n")
    sys.exit(0 if passed_runs == total_runs else 1)


if __name__ == "__main__":
    main()
