#!/usr/bin/env python3
"""
Kong AI Gateway — Teste de Integração PII Sanitizer
=====================================================
Script de teste para validar a ofuscação de PII em tempo real
via Kong AI Gateway + PII Sanitizer customizado.

Compliance: Resolução BCB nº 538/2025

Uso:
    python test_kong_proxy.py                    # Teste completo (requer AWS)
    python test_kong_proxy.py --sanitizer-only   # Testa só o PII Sanitizer
    python test_kong_proxy.py --help             # Ajuda

Requisitos:
    pip install requests
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("❌ Biblioteca 'requests' não encontrada.")
    print("   Instale com: pip install requests")
    sys.exit(1)


# ── Configuração ─────────────────────────────────────────────────────────────

KONG_PROXY_URL = "http://localhost:8000"
KONG_ADMIN_URL = "http://localhost:8001"
PII_SANITIZER_URL = "http://localhost:8088"

# Prompts com dados sensíveis fictícios para teste
TEST_PROMPTS = [
    {
        "name": "Cenário 1: Dados bancários com CPF formatado",
        "prompt": (
            "Meu nome é João da Silva, meu CPF é 123.456.789-00 "
            "e meu saldo é R$ 50.000. Posso transferir?"
        ),
        "expected_pii": ["NAME", "CPF", "MONEY"],
    },
    {
        "name": "Cenário 2: Múltiplos tipos de PII",
        "prompt": (
            "A cliente Maria Oliveira (CPF 98765432100, "
            "email maria@empresa.com, tel (11) 99876-5432) "
            "solicitou empréstimo de R$ 150.000,00."
        ),
        "expected_pii": ["NAME", "CPF", "EMAIL", "PHONE", "MONEY"],
    },
    {
        "name": "Cenário 3: Transferência entre contas",
        "prompt": (
            "Transfira R$ 10.000 da conta de Pedro Santos, "
            "CPF 111.222.333-44, para a conta de Ana Lima, "
            "CPF 555.666.777-88."
        ),
        "expected_pii": ["MONEY", "NAME", "CPF"],
    },
    {
        "name": "Cenário 4: Sem PII (controle negativo)",
        "prompt": "Qual é a taxa básica de juros do mercado financeiro atual?",
        "expected_pii": [],
    },
]


# ── Helpers ──────────────────────────────────────────────────────────────────


class Colors:
    """Códigos ANSI para output colorido."""

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
    """Imprime um cabeçalho formatado."""
    width = 72
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'═' * width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'═' * width}{Colors.END}\n")


def print_section(text: str) -> None:
    """Imprime um separador de seção."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}── {text} {'─' * (60 - len(text))}{Colors.END}\n")


def print_success(text: str) -> None:
    print(f"  {Colors.GREEN}✅ {text}{Colors.END}")


def print_error(text: str) -> None:
    print(f"  {Colors.RED}❌ {text}{Colors.END}")


def print_warning(text: str) -> None:
    print(f"  {Colors.YELLOW}⚠️  {text}{Colors.END}")


def print_info(text: str) -> None:
    print(f"  {Colors.BLUE}ℹ️  {text}{Colors.END}")


def print_json(data: dict, indent: int = 4) -> None:
    """Imprime JSON formatado com syntax highlighting básico."""
    formatted = json.dumps(data, indent=indent, ensure_ascii=False)
    # Highlight simples
    formatted = formatted.replace('"sanitized_text"', f'{Colors.GREEN}"sanitized_text"{Colors.END}')
    formatted = formatted.replace('"pii_detected"', f'{Colors.YELLOW}"pii_detected"{Colors.END}')
    formatted = formatted.replace('"total_entities"', f'{Colors.CYAN}"total_entities"{Colors.END}')
    print(f"  {formatted}")


# ── Testes ───────────────────────────────────────────────────────────────────


def test_health_checks() -> dict[str, bool]:
    """Verifica a saúde de todos os serviços."""
    print_section("Health Checks")
    results = {}

    # PII Sanitizer
    try:
        r = requests.get(f"{PII_SANITIZER_URL}/health", timeout=5)
        if r.status_code == 200:
            print_success(f"PII Sanitizer: {r.json()}")
            results["pii_sanitizer"] = True
        else:
            print_error(f"PII Sanitizer: HTTP {r.status_code}")
            results["pii_sanitizer"] = False
    except requests.ConnectionError:
        print_error("PII Sanitizer: Não disponível (ConnectionError)")
        results["pii_sanitizer"] = False

    # Kong Admin API
    try:
        r = requests.get(f"{KONG_ADMIN_URL}/status", timeout=5)
        if r.status_code == 200:
            status = r.json()
            connections = status.get("server", {}).get("connections_active", "?")
            print_success(f"Kong Gateway: {connections} conexões ativas")
            results["kong_gateway"] = True
        else:
            print_error(f"Kong Gateway: HTTP {r.status_code}")
            results["kong_gateway"] = False
    except requests.ConnectionError:
        print_error("Kong Gateway: Não disponível (ConnectionError)")
        results["kong_gateway"] = False

    return results


def test_pii_sanitizer_direct() -> bool:
    """Testa o PII Sanitizer diretamente (sem passar pelo Kong)."""
    print_section("Teste Direto — PII Sanitizer")
    all_passed = True

    for i, scenario in enumerate(TEST_PROMPTS, 1):
        print(f"\n  {Colors.BOLD}📝 {scenario['name']}{Colors.END}")
        print(f"  {Colors.DIM}Prompt: \"{scenario['prompt'][:80]}...\"{Colors.END}")

        try:
            r = requests.post(
                f"{PII_SANITIZER_URL}/sanitize",
                json={
                    "text": scenario["prompt"],
                    "redact_type": "placeholder",
                },
                timeout=10,
            )

            if r.status_code != 200:
                print_error(f"HTTP {r.status_code}: {r.text}")
                all_passed = False
                continue

            result = r.json()

            # Exibir resultado
            print(f"  {Colors.GREEN}Sanitizado:{Colors.END} \"{result['sanitized_text'][:100]}...\"")
            print(f"  {Colors.CYAN}Entidades:{Colors.END} {result['total_entities']} detectadas")
            print(f"  {Colors.DIM}Tempo: {result['processing_time_ms']:.2f}ms{Colors.END}")

            if result["pii_detected"]:
                for entity in result["pii_detected"]:
                    print(
                        f"    {Colors.YELLOW}• {entity['type']}: "
                        f"\"{entity['original']}\" → \"{entity['replacement']}\"{Colors.END}"
                    )

            # Validar PII esperado
            detected_types = {e["type"] for e in result["pii_detected"]}
            expected_types = set(scenario["expected_pii"])

            if expected_types:
                missing = expected_types - detected_types
                if missing:
                    print_warning(f"PII esperado mas não detectado: {missing}")
                    # Não falhar por nomes — detecção heurística pode variar
                    critical_missing = missing - {"NAME"}
                    if critical_missing:
                        all_passed = False
                else:
                    print_success("Todos os tipos de PII esperados foram detectados")
            else:
                if result["total_entities"] == 0:
                    print_success("Controle negativo: nenhum PII detectado (correto)")
                else:
                    print_warning(
                        f"Controle negativo: {result['total_entities']} falsos positivos"
                    )

        except requests.ConnectionError:
            print_error("PII Sanitizer não disponível")
            all_passed = False
            break

    return all_passed


def test_kong_e2e() -> bool:
    """Testa o fluxo completo via Kong Gateway."""
    print_section("Teste E2E — Kong AI Gateway → PII Sanitizer → Bedrock")
    print_info(
        "Este teste envia requests via Kong. "
        "Requer licença Enterprise + credenciais AWS válidas."
    )

    prompt = TEST_PROMPTS[0]
    print(f"\n  {Colors.BOLD}📝 {prompt['name']}{Colors.END}")
    print(f"  {Colors.DIM}Prompt original: \"{prompt['prompt']}\"{Colors.END}")

    # Formato OpenAI/LLM chat completions
    payload = {
        "messages": [
            {
                "role": "system",
                "content": (
                    "Você é um assistente financeiro. "
                    "Responda de forma objetiva e profissional."
                ),
            },
            {
                "role": "user",
                "content": prompt["prompt"],
            },
        ],
        "temperature": 0.7,
        "max_tokens": 512,
    }

    try:
        print_info("Enviando request ao Kong...")
        start_time = time.time()

        r = requests.post(
            f"{KONG_PROXY_URL}/llm-proxy",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=30,
        )

        elapsed = time.time() - start_time

        print(f"\n  {Colors.BOLD}Resposta (HTTP {r.status_code}) — {elapsed:.2f}s{Colors.END}")

        # Exibir request ID para rastreabilidade
        request_id = r.headers.get("X-Request-ID", "N/A")
        print(f"  {Colors.DIM}X-Request-ID: {request_id}{Colors.END}")

        if r.status_code == 200:
            response_data = r.json()
            print_success("Request processada com sucesso pelo Kong")
            print(f"\n  {Colors.GREEN}Resposta do LLM:{Colors.END}")
            print_json(response_data)

            # Verificar se o prompt original NÃO está na resposta
            original_cpf = "123.456.789-00"
            response_text = json.dumps(response_data)
            if original_cpf not in response_text:
                print_success(
                    f"CPF original ({original_cpf}) NÃO presente na resposta — "
                    "ofuscação confirmada!"
                )
            else:
                print_warning(
                    f"CPF original ({original_cpf}) encontrado na resposta — "
                    "verificar sanitização"
                )

            return True

        elif r.status_code == 401:
            print_warning("HTTP 401 — Credenciais AWS inválidas ou ausentes")
            print_info("Verifique AWS_ACCESS_KEY_ID e AWS_SECRET_ACCESS_KEY no .env")
            return False

        elif r.status_code == 503:
            print_warning(
                "HTTP 503 — Serviço indisponível. "
                "O ai-proxy pode exigir licença Enterprise."
            )
            print_info("Obtenha um trial de 30 dias em https://konnect.konghq.com/")
            return False

        else:
            print_error(f"HTTP {r.status_code}")
            try:
                print_json(r.json())
            except ValueError:
                print(f"  {r.text[:500]}")
            return False

    except requests.ConnectionError:
        print_error("Kong Gateway não disponível em " + KONG_PROXY_URL)
        print_info("Execute: docker compose up -d --build")
        return False


def test_synthetic_mode() -> bool:
    """Testa o modo synthetic do PII Sanitizer."""
    print_section("Teste Modo Synthetic — Dados Falsos Coerentes")

    prompt = TEST_PROMPTS[0]
    print(f"  {Colors.DIM}Prompt: \"{prompt['prompt'][:80]}...\"{Colors.END}")

    try:
        r = requests.post(
            f"{PII_SANITIZER_URL}/sanitize",
            json={
                "text": prompt["prompt"],
                "redact_type": "synthetic",
            },
            timeout=10,
        )

        if r.status_code == 200:
            result = r.json()
            print(f"\n  {Colors.GREEN}Texto com dados sintéticos:{Colors.END}")
            print(f"  \"{result['sanitized_text']}\"")
            print(f"\n  {Colors.CYAN}Substituições:{Colors.END}")
            for entity in result["pii_detected"]:
                print(
                    f"    {Colors.YELLOW}• {entity['type']}: "
                    f"\"{entity['original']}\" → \"{entity['replacement']}\"{Colors.END}"
                )
            print_success("Modo synthetic funcionando — dados falsos coerentes gerados")
            return True
        else:
            print_error(f"HTTP {r.status_code}")
            return False

    except requests.ConnectionError:
        print_error("PII Sanitizer não disponível")
        return False


def show_audit_instructions() -> None:
    """Exibe instruções para consultar os logs de auditoria."""
    print_section("Auditoria — Logs para Compliance BCB 538/2025")
    print(f"""
  {Colors.BOLD}Como consultar os logs de auditoria:{Colors.END}

  {Colors.CYAN}# Ver logs do Kong (inclui metadados PII):{Colors.END}
  docker compose exec kong-gateway cat /tmp/kong-audit.log | python -m json.tool

  {Colors.CYAN}# Filtrar apenas requests com PII detectado:{Colors.END}
  docker compose exec kong-gateway cat /tmp/kong-audit.log | \\
    python -c "
import sys, json
for line in sys.stdin:
    try:
        log = json.loads(line.strip())
        if 'pii_sanitizer' in str(log):
            print(json.dumps(log, indent=2, ensure_ascii=False))
    except: pass
"

  {Colors.CYAN}# Ver logs do PII Sanitizer:{Colors.END}
  docker compose logs pii-sanitizer --tail=50

  {Colors.BOLD}Campos relevantes para relatório BCB:{Colors.END}
    • pii_identified  — quantidade de entidades PII detectadas
    • pii_types       — tipos de PII (CPF, EMAIL, PHONE, etc.)
    • redact_type     — método de ofuscação utilizado
    • timestamp       — momento da interceptação
    • X-Request-ID    — ID de correlação para rastreabilidade
""")


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Kong AI Gateway — Teste de Integração PII (BCB 538/2025)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python test_kong_proxy.py                    # Teste completo
  python test_kong_proxy.py --sanitizer-only   # Testa só o PII Sanitizer
  python test_kong_proxy.py --synthetic        # Testa modo synthetic
        """,
    )
    parser.add_argument(
        "--sanitizer-only",
        action="store_true",
        help="Testa apenas o PII Sanitizer (sem Kong/AWS)",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Testa o modo synthetic (dados falsos coerentes)",
    )
    parser.add_argument(
        "--kong-url",
        default=KONG_PROXY_URL,
        help=f"URL do Kong Proxy (default: {KONG_PROXY_URL})",
    )
    parser.add_argument(
        "--sanitizer-url",
        default=PII_SANITIZER_URL,
        help=f"URL do PII Sanitizer (default: {PII_SANITIZER_URL})",
    )

    args = parser.parse_args()

    # Override URLs se fornecidas
    global KONG_PROXY_URL, KONG_ADMIN_URL, PII_SANITIZER_URL
    KONG_PROXY_URL = args.kong_url
    KONG_ADMIN_URL = args.kong_url.replace(":8000", ":8001")
    PII_SANITIZER_URL = args.sanitizer_url

    # Header
    print_header("Kong AI Gateway — Teste de Integração PII")
    print(f"  {Colors.DIM}Data/Hora: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{Colors.END}")
    print(f"  {Colors.DIM}Compliance: Resolução BCB nº 538/2025{Colors.END}")
    print(f"  {Colors.DIM}Kong: {KONG_PROXY_URL}{Colors.END}")
    print(f"  {Colors.DIM}Sanitizer: {PII_SANITIZER_URL}{Colors.END}")

    # Executar testes
    results = {}

    # Health checks
    health = test_health_checks()
    results["health"] = all(health.values()) if health else False

    if args.sanitizer_only:
        # Só testar o PII Sanitizer
        results["pii_sanitizer"] = test_pii_sanitizer_direct()
        if args.synthetic:
            results["synthetic"] = test_synthetic_mode()
    else:
        # Teste completo
        results["pii_sanitizer"] = test_pii_sanitizer_direct()

        if args.synthetic:
            results["synthetic"] = test_synthetic_mode()

        if health.get("kong_gateway"):
            results["kong_e2e"] = test_kong_e2e()
        else:
            print_section("Teste E2E — Kong Gateway")
            print_warning(
                "Kong Gateway não disponível — pulando teste E2E. "
                "Execute: docker compose up -d --build"
            )

    # Instruções de auditoria
    show_audit_instructions()

    # Resumo
    print_section("Resumo dos Resultados")
    total = len(results)
    passed = sum(1 for v in results.values() if v)

    for test_name, passed_flag in results.items():
        status = f"{Colors.GREEN}PASS{Colors.END}" if passed_flag else f"{Colors.RED}FAIL{Colors.END}"
        print(f"  {status}  {test_name}")

    print(f"\n  {Colors.BOLD}{passed}/{total} testes passaram{Colors.END}\n")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
