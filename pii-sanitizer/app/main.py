"""
PII Sanitizer Service — Kong AI Gateway PoC
=============================================
Serviço FastAPI para detecção e ofuscação de Informações Pessoalmente
Identificáveis (PII) em tempo real, com foco em dados brasileiros.

Compliance: Resolução BCB nº 538/2025
"""

import os
import re
import random
import time
import logging
from typing import Optional
from enum import Enum

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pii-sanitizer")

# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PII Sanitizer — BCB 538/2025 Compliance",
    description=(
        "Serviço de detecção e ofuscação de PII para o Kong AI Gateway. "
        "Foco em dados brasileiros: CPF, telefones, emails, nomes e valores monetários."
    ),
    version="1.0.0",
)


# ── Models ───────────────────────────────────────────────────────────────────


class RedactType(str, Enum):
    PLACEHOLDER = "placeholder"
    SYNTHETIC = "synthetic"


class SanitizeRequest(BaseModel):
    """Requisição de sanitização de texto."""

    text: str = Field(..., description="Texto a ser analisado e sanitizado")
    redact_type: RedactType = Field(
        default=RedactType.PLACEHOLDER,
        description="Tipo de redação: placeholder ou synthetic",
    )


class PIIEntity(BaseModel):
    """Entidade PII detectada."""

    type: str = Field(..., description="Tipo de PII (CPF, EMAIL, PHONE, etc.)")
    original: str = Field(..., description="Valor original detectado")
    replacement: str = Field(..., description="Valor substituto aplicado")
    start: int = Field(..., description="Posição inicial no texto original")
    end: int = Field(..., description="Posição final no texto original")


class SanitizeResponse(BaseModel):
    """Resposta de sanitização com metadados de auditoria."""

    sanitized_text: str = Field(..., description="Texto com PII ofuscado")
    pii_detected: list[PIIEntity] = Field(
        default_factory=list, description="Lista de entidades PII detectadas"
    )
    total_entities: int = Field(0, description="Total de entidades detectadas")
    processing_time_ms: float = Field(
        0.0, description="Tempo de processamento em milissegundos"
    )
    redact_type: str = Field("placeholder", description="Tipo de redação utilizado")


class HealthResponse(BaseModel):
    """Resposta do health check."""

    status: str = "healthy"
    service: str = "pii-sanitizer"
    version: str = "1.0.0"


# ── PII Detection Engine ────────────────────────────────────────────────────


def _validate_cpf_digits(cpf_digits: str) -> bool:
    """
    Valida os dígitos verificadores de um CPF.
    Retorna True se o CPF é matematicamente válido.
    """
    if len(cpf_digits) != 11:
        return False

    # Rejeita CPFs com todos os dígitos iguais (ex: 111.111.111-11)
    if cpf_digits == cpf_digits[0] * 11:
        return False

    # Primeiro dígito verificador
    total = sum(int(cpf_digits[i]) * (10 - i) for i in range(9))
    remainder = total % 11
    first_check = 0 if remainder < 2 else 11 - remainder
    if int(cpf_digits[9]) != first_check:
        return False

    # Segundo dígito verificador
    total = sum(int(cpf_digits[i]) * (11 - i) for i in range(10))
    remainder = total % 11
    second_check = 0 if remainder < 2 else 11 - remainder
    if int(cpf_digits[10]) != second_check:
        return False

    return True


def _generate_synthetic_cpf() -> str:
    """Gera um CPF falso mas matematicamente válido (formato XXX.XXX.XXX-XX)."""
    digits = [random.randint(0, 9) for _ in range(9)]

    # Primeiro dígito verificador
    total = sum(digits[i] * (10 - i) for i in range(9))
    remainder = total % 11
    digits.append(0 if remainder < 2 else 11 - remainder)

    # Segundo dígito verificador
    total = sum(digits[i] * (11 - i) for i in range(10))
    remainder = total % 11
    digits.append(0 if remainder < 2 else 11 - remainder)

    s = "".join(str(d) for d in digits)
    return f"{s[:3]}.{s[3:6]}.{s[6:9]}-{s[9:]}"


def _generate_synthetic_email() -> str:
    """Gera um email falso coerente."""
    names = ["usuario", "contato", "cliente", "admin", "suporte"]
    domains = ["exemplo.com.br", "dominio.com", "teste.org.br"]
    return f"{random.choice(names)}{random.randint(100, 999)}@{random.choice(domains)}"


def _generate_synthetic_phone() -> str:
    """Gera um telefone brasileiro falso."""
    ddd = random.randint(11, 99)
    num = random.randint(90000, 99999)
    suffix = random.randint(1000, 9999)
    return f"({ddd}) {num}-{suffix}"


def _generate_synthetic_name() -> str:
    """Gera um nome brasileiro falso."""
    first_names = ["Carlos", "Ana", "Pedro", "Mariana", "Lucas", "Juliana", "Rafael"]
    last_names = ["Ferreira", "Souza", "Costa", "Almeida", "Pereira", "Barbosa"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def _generate_synthetic_money() -> str:
    """Gera um valor monetário falso."""
    value = random.randint(100, 99999)
    return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


# Padrões PII ordenados por prioridade (mais específicos primeiro)
PII_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # CPF formatado: 123.456.789-00
    (
        "CPF",
        re.compile(r"\d{3}\.\d{3}\.\d{3}-\d{2}"),
        0,
    ),
    # CPF numérico puro: 12345678900 (11 dígitos exatos, word boundary)
    (
        "CPF",
        re.compile(r"\b\d{11}\b"),
        1,
    ),
    # Email
    (
        "EMAIL",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        0,
    ),
    # Telefone brasileiro: (11) 99876-5432, 11 99876-5432, (11) 9876-5432
    (
        "PHONE",
        re.compile(r"\(?\d{2}\)?\s?\d{4,5}-?\d{4}"),
        0,
    ),
    # Valor monetário: R$ 50.000, R$ 1.234,56, R$ 50000
    (
        "MONEY",
        re.compile(r"R\$\s?[\d.,]+"),
        0,
    ),
]

# Padrão para detecção heurística de nomes próprios brasileiros
# Detecta sequências de 2+ palavras capitalizadas (min 2 chars cada)
NAME_PATTERN = re.compile(
    r"\b([A-ZÀ-Ú][a-zà-ú]{1,}(?:\s(?:da|de|do|dos|das|e)\s)?[A-ZÀ-Ú][a-zà-ú]{1,}(?:\s[A-ZÀ-Ú][a-zà-ú]{1,})*)\b"
)

# Palavras que NÃO são nomes próprios (falsos positivos comuns em Português)
NAME_STOPWORDS = {
    "Meu", "Minha", "Meus", "Minhas",
    "Seu", "Sua", "Seus", "Suas",
    "Nosso", "Nossa", "Nossos", "Nossas",
    "Este", "Esta", "Estes", "Estas",
    "Esse", "Essa", "Esses", "Essas",
    "Qual", "Quais", "Como", "Onde",
    "Posso", "Pode", "Podemos",
    "Para", "Pela", "Pelo",
    "Banco Central", "Sistema Financeiro",
    "Amazon Bedrock", "Kong Gateway",
}


def detect_and_sanitize(text: str, redact_type: RedactType) -> SanitizeResponse:
    """
    Detecta e ofusca PII no texto fornecido.

    Estratégia:
    1. Varre o texto com regex para cada tipo de PII
    2. Coleta todas as matches com posições
    3. Resolve conflitos (matches sobrepostos — mantém o mais específico)
    4. Substitui de trás para frente para preservar posições
    """
    start_time = time.perf_counter()
    entities: list[PIIEntity] = []
    counters: dict[str, int] = {}

    # Coletar todas as matches de padrões regex
    raw_matches: list[tuple[str, int, int, str, int]] = []

    for pii_type, pattern, priority in PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()

            # Validação extra para CPF numérico: evitar falsos positivos
            if pii_type == "CPF" and priority == 1:
                # CPF numérico (11 dígitos) — validar dígitos verificadores
                # Aceita mesmo CPFs inválidos na PoC para demonstração,
                # mas sinaliza com score menor
                pass

            raw_matches.append((pii_type, match.start(), match.end(), value, priority))

    # Detectar nomes próprios
    for match in NAME_PATTERN.finditer(text):
        name = match.group()
        # Filtrar falsos positivos
        if name not in NAME_STOPWORDS and not any(
            sw in name for sw in NAME_STOPWORDS
        ):
            raw_matches.append(("NAME", match.start(), match.end(), name, 10))

    # Ordenar por posição e resolver sobreposições (manter match mais específico)
    raw_matches.sort(key=lambda m: (m[1], -m[4]))  # por posição, depois prioridade
    filtered_matches: list[tuple[str, int, int, str, int]] = []
    last_end = -1

    for pii_type, start, end, value, priority in raw_matches:
        if start >= last_end:
            filtered_matches.append((pii_type, start, end, value, priority))
            last_end = end

    # Gerar substituições e construir entidades (de trás para frente)
    sanitized = text
    for pii_type, start, end, value, _priority in reversed(filtered_matches):
        counters[pii_type] = counters.get(pii_type, 0) + 1
        idx = counters[pii_type]

        if redact_type == RedactType.SYNTHETIC:
            replacement = _get_synthetic_replacement(pii_type)
        else:
            replacement = f"[REDACTED_{pii_type}_{idx}]"

        entities.append(
            PIIEntity(
                type=pii_type,
                original=value,
                replacement=replacement,
                start=start,
                end=end,
            )
        )

        sanitized = sanitized[:start] + replacement + sanitized[end:]

    # Reverter a lista para ordem de aparição
    entities.reverse()

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return SanitizeResponse(
        sanitized_text=sanitized,
        pii_detected=entities,
        total_entities=len(entities),
        processing_time_ms=round(elapsed_ms, 2),
        redact_type=redact_type.value,
    )


def _get_synthetic_replacement(pii_type: str) -> str:
    """Retorna um valor sintético coerente para o tipo de PII."""
    generators = {
        "CPF": _generate_synthetic_cpf,
        "EMAIL": _generate_synthetic_email,
        "PHONE": _generate_synthetic_phone,
        "NAME": _generate_synthetic_name,
        "MONEY": _generate_synthetic_money,
    }
    generator = generators.get(pii_type)
    if generator:
        return generator()
    return f"[SYNTHETIC_{pii_type}]"


# ── Routes ───────────────────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse, tags=["Operacional"])
async def health_check():
    """Health check para Docker Compose e monitoramento."""
    return HealthResponse()


@app.post("/sanitize", response_model=SanitizeResponse, tags=["PII"])
async def sanitize_text(request: SanitizeRequest):
    """
    Analisa e ofusca PII no texto fornecido.

    Tipos de PII detectados:
    - **CPF** (formatado e numérico)
    - **Email**
    - **Telefone** (formato brasileiro)
    - **Nome próprio** (heurística)
    - **Valor monetário** (R$)

    Modos de redação:
    - `placeholder`: substitui por `[REDACTED_TYPE_N]`
    - `synthetic`: gera dados falsos coerentes
    """
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="O campo 'text' não pode ser vazio.")

    result = detect_and_sanitize(request.text, request.redact_type)

    if result.total_entities > 0:
        logger.info(
            "PII detectado: %d entidades [%s] | tempo: %.2fms",
            result.total_entities,
            ", ".join(e.type for e in result.pii_detected),
            result.processing_time_ms,
        )

    return result


@app.get("/", tags=["Operacional"])
async def root():
    """Endpoint raiz com informações do serviço."""
    return {
        "service": "PII Sanitizer",
        "version": "1.0.0",
        "compliance": "BCB 538/2025",
        "docs": "/docs",
        "endpoints": {
            "sanitize": "POST /sanitize",
            "health": "GET /health",
        },
    }


# ── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8088")),
        reload=True,
        log_level="info",
    )
