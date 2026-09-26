"""
PII Engine — Regex & Checksum Detection with Synthetic Generators
===================================================================
Detects Brazilian financial and personal PII data (CPF, CNPJ, Bank Accounts,
Emails, Phones, Names, Money) and performs redaction or synthetic substitution.
"""

import re
import random
import time
from typing import List, Dict, Tuple, Optional
from app.schemas import RedactType, PIIEntity, SanitizeResponse


# ── Checksum Verification Helper Functions ────────────────────────────────────


def validate_cpf_digits(cpf_digits: str) -> bool:
    """Validates a Brazilian CPF checksum (11 digits)."""
    if len(cpf_digits) != 11 or not cpf_digits.isdigit() or cpf_digits == cpf_digits[0] * 11:
        return False

    total = sum(int(cpf_digits[i]) * (10 - i) for i in range(9))
    remainder = total % 11
    first_check = 0 if remainder < 2 else 11 - remainder
    if int(cpf_digits[9]) != first_check:
        return False

    total = sum(int(cpf_digits[i]) * (11 - i) for i in range(10))
    remainder = total % 11
    second_check = 0 if remainder < 2 else 11 - remainder
    return int(cpf_digits[10]) == second_check


def validate_cnpj_digits(cnpj_digits: str) -> bool:
    """Validates a Brazilian CNPJ checksum (14 digits)."""
    if len(cnpj_digits) != 14 or not cnpj_digits.isdigit() or cnpj_digits == cnpj_digits[0] * 14:
        return False

    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(cnpj_digits[i]) * weights_1[i] for i in range(12))
    remainder = total % 11
    first_check = 0 if remainder < 2 else 11 - remainder
    if int(cnpj_digits[12]) != first_check:
        return False

    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(cnpj_digits[i]) * weights_2[i] for i in range(13))
    remainder = total % 11
    second_check = 0 if remainder < 2 else 11 - remainder
    return int(cnpj_digits[13]) == second_check


# ── Synthetic Generator Functions ─────────────────────────────────────────────


def generate_synthetic_cpf() -> str:
    """Generates a mathematically valid, synthetic Brazilian CPF (XXX.XXX.XXX-XX)."""
    digits = [random.randint(0, 9) for _ in range(9)]
    total = sum(digits[i] * (10 - i) for i in range(9))
    rem = total % 11
    digits.append(0 if rem < 2 else 11 - rem)

    total = sum(digits[i] * (11 - i) for i in range(10))
    rem = total % 11
    digits.append(0 if rem < 2 else 11 - rem)

    s = "".join(str(d) for d in digits)
    return f"{s[:3]}.{s[3:6]}.{s[6:9]}-{s[9:]}"


def generate_synthetic_cnpj() -> str:
    """Generates a mathematically valid, synthetic Brazilian CNPJ (XX.XXX.XXX/0001-XX)."""
    digits = [random.randint(0, 9) for _ in range(8)] + [0, 0, 0, 1]
    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(digits[i] * weights_1[i] for i in range(12))
    rem = total % 11
    digits.append(0 if rem < 2 else 11 - rem)

    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(digits[i] * weights_2[i] for i in range(13))
    rem = total % 11
    digits.append(0 if rem < 2 else 11 - rem)

    s = "".join(str(d) for d in digits)
    return f"{s[:2]}.{s[2:5]}.{s[5:8]}/{s[8:12]}-{s[12:]}"


def generate_synthetic_email() -> str:
    names = ["cliente", "usuario", "contato", "gestor", "analista"]
    domains = ["bancoexemplo.com.br", "financeiro.com.br", "sandbox.net.br"]
    return f"{random.choice(names)}{random.randint(100, 999)}@{random.choice(domains)}"


def generate_synthetic_phone() -> str:
    ddd = random.randint(11, 99)
    num = random.randint(90000, 99999)
    suffix = random.randint(1000, 9999)
    return f"({ddd}) {num}-{suffix}"


def generate_synthetic_name() -> str:
    first_names = ["Carlos", "Mariana", "Lucas", "Beatriz", "Gabriel", "Fernanda", "Rodrigo", "Camila"]
    last_names = ["Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira", "Almeida", "Pereira"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def generate_synthetic_money() -> str:
    val = random.randint(500, 250000)
    return f"R$ {val:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def generate_synthetic_bank_account() -> str:
    ag = random.randint(1000, 9999)
    cc = random.randint(10000, 99999)
    dig = random.randint(0, 9)
    return f"Agência {ag} Conta {cc}-{dig}"


# ── Compiled Patterns and Priorities ──────────────────────────────────────────

PII_PATTERNS: List[Tuple[str, re.Pattern, int]] = [
    # Formatted CPF: 123.456.789-00
    ("CPF", re.compile(r"\d{3}\.\d{3}\.\d{3}-\d{2}"), 0),
    # Raw CPF: 11 exact digits
    ("CPF", re.compile(r"\b\d{11}\b"), 1),
    # Formatted CNPJ: 12.345.678/0001-90
    ("CNPJ", re.compile(r"\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}"), 0),
    # Raw CNPJ: 14 exact digits
    ("CNPJ", re.compile(r"\b\d{14}\b"), 1),
    # Email
    ("EMAIL", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), 0),
    # Phone numbers: captures Brazilian mobile/landline formats while excluding arbitrary digit sequences
    (
        "PHONE",
        re.compile(
            r"(?:\([1-9]{2}\)\s?|\b[1-9]{2}\s?)(?:9\d{4}|[2-5]\d{3})[-\s]?\d{4}\b|\b(?:9\d{4}|[2-5]\d{3})-\d{4}\b"
        ),
        0,
    ),
    # Currency: trimmed so trailing punctuation (. or ,) is never captured
    ("MONEY", re.compile(r"R\$\s*[\d.,]*\d"), 0),
    # Compound Bank Account: keyword-separated (e.g. Agência <digits> ... Conta <digits>-<dig>)
    (
        "BANK_ACCOUNT",
        re.compile(
            r"\b(?:ag(?:[eê]ncia|\.)?|ag)\s*:?\s*\d{1,5}(?:-[0-9kKxX])?\s*[,/]?\s+(?:(?:op(?:era[cç][aã]o)?\s*:?\s*\d{1,4}\s+)?(?:conta(?:\s*corrente)?|c/c|cc|cta)\b\.?\s*:?\s*\d{3,9}(?:-[0-9kKxX])?)\b"
            r"|"
            r"\b(?:conta(?:\s*corrente)?|c/c|cc|cta)\b\.?\s*:?\s*\d{3,9}(?:-[0-9kKxX])?\s*[,/]?\s+(?:ag(?:[eê]ncia|\.)?|ag)\s*:?\s*\d{1,5}(?:-[0-9kKxX])?\b",
            re.IGNORECASE,
        ),
        2,
    ),
    # Contiguous Bank Account
    ("BANK_ACCOUNT", re.compile(r"\b(?:ag(?:ência)?|conta|c/c)\s*:?\s*\d{3,5}[-\s]?\d{3,7}[-\s]?[0-9kK]?\b", re.IGNORECASE), 0),
]

NAME_PATTERN = re.compile(
    r"\b([A-ZÀ-Ú][a-zà-ú]{1,}(?:\s(?:da|de|do|dos|das|e))?\s[A-ZÀ-Ú][a-zà-ú]{1,}(?:\s[A-ZÀ-Ú][a-zà-ú]{1,})*)\b"
)

NORMALIZED_STOPWORDS = {
    "meu", "minha", "meus", "minhas", "seu", "sua", "seus", "suas",
    "nosso", "nossa", "nossos", "nossas", "este", "esta", "estes", "estas",
    "esse", "essa", "esses", "essas", "qual", "quais", "como", "onde",
    "posso", "pode", "podemos", "para", "pela", "pelo", "banco central",
    "sistema financeiro", "amazon bedrock", "kong gateway", "resolucao cmn",
    "transferencia", "transferência", "agencia", "agência", "ag", "conta",
    "banco", "saldo", "extrato", "deposito", "depósito", "pagamento",
    "pix", "ted", "doc", "comprovante", "pedido", "nota", "fatura",
    "cliente", "usuario", "usuário", "solicitacao", "solicitação",
    "confirmada", "confirmado",
}


def normalize_entity_key(pii_type: str, value: str) -> str:
    """Normalizes an entity value to a canonical key for deterministic matching."""
    if pii_type in ("CPF", "CNPJ"):
        return f"{pii_type}:{re.sub(r'\D', '', value)}"
    elif pii_type in ("EMAIL", "NAME"):
        return f"{pii_type}:{value.strip().lower()}"
    elif pii_type == "PHONE":
        return f"{pii_type}:{re.sub(r'\D', '', value)}"
    elif pii_type == "BANK_ACCOUNT":
        norm = re.sub(r"[\s:.-]", "", value.lower())
        return f"{pii_type}:{norm}"
    elif pii_type == "MONEY":
        norm = re.sub(r"[\s]", "", value.lower()).rstrip(".,")
        return f"{pii_type}:{norm}"
    return f"{pii_type}:{value.strip()}"


def _format_synthetic(pii_type: str, raw_synthetic: str, original_value: str) -> str:
    """Formats the generated synthetic value to match the formatting style of the original."""
    if pii_type in ("CPF", "CNPJ"):
        if re.match(r"^\d+$", original_value):
            return re.sub(r"\D", "", raw_synthetic)
    return raw_synthetic


# ── Core Engine Function ──────────────────────────────────────────────────────


def detect_and_sanitize(
    text: str,
    redact_type: RedactType,
    entity_map: Optional[Dict[str, str]] = None,
) -> SanitizeResponse:
    """Scans input text, detects Brazilian PII entities, and applies redactions."""
    start_time = time.perf_counter()
    entities: List[PIIEntity] = []
    counters: Dict[str, int] = {}
    raw_matches: List[Tuple[str, int, int, str, int, Optional[bool]]] = []

    # Local synthetic map seeded by caller's entity_map if provided
    synthetic_map: Dict[str, str] = {}
    if entity_map is not None:
        synthetic_map.update(entity_map)

    # 1. Regex scanning
    for pii_type, pattern, priority in PII_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()
            checksum_valid: Optional[bool] = None

            if pii_type == "CPF":
                digits = re.sub(r"\D", "", value)
                is_valid = validate_cpf_digits(digits)
                is_raw = bool(re.match(r"^\d{11}$", value))
                if is_raw:
                    if not is_valid:
                        continue  # Raw 11-digit numbers are only treated as CPF if checksum passes
                    checksum_valid = True
                else:
                    checksum_valid = is_valid

            elif pii_type == "CNPJ":
                digits = re.sub(r"\D", "", value)
                is_valid = validate_cnpj_digits(digits)
                is_raw = bool(re.match(r"^\d{14}$", value))
                if is_raw:
                    if not is_valid:
                        continue  # Raw 14-digit numbers are only treated as CNPJ if checksum passes
                    checksum_valid = True
                else:
                    checksum_valid = is_valid

            raw_matches.append((pii_type, match.start(), match.end(), value, priority, checksum_valid))

    # 2. Name heuristic scanning
    for match in NAME_PATTERN.finditer(text):
        name = match.group()
        name_lower = name.lower()
        words = name_lower.split()
        is_stop = (
            name_lower in NORMALIZED_STOPWORDS
            or any(w in NORMALIZED_STOPWORDS for w in words)
            or any(sw in name_lower for sw in NORMALIZED_STOPWORDS if " " in sw)
        )
        if not is_stop:
            raw_matches.append(("NAME", match.start(), match.end(), name, 10, None))

    # 3. Conflict resolution
    raw_matches.sort(key=lambda m: (m[1], -m[4]))
    filtered_matches: List[Tuple[str, int, int, str, int, Optional[bool]]] = []
    last_end = -1

    for pii_type, start, end, value, priority, checksum_valid in raw_matches:
        if start >= last_end:
            filtered_matches.append((pii_type, start, end, value, priority, checksum_valid))
            last_end = end

    # 4. Pre-assign synthetic values in forward occurrence order
    if redact_type == RedactType.SYNTHETIC:
        for pii_type, start, end, value, _, _ in filtered_matches:
            canon_key = normalize_entity_key(pii_type, value)
            if canon_key not in synthetic_map:
                synthetic_map[canon_key] = _get_synthetic(pii_type)

    # 5. Replacement in reverse order
    sanitized = text
    for pii_type, start, end, value, _, checksum_valid in reversed(filtered_matches):
        counters[pii_type] = counters.get(pii_type, 0) + 1
        idx = counters[pii_type]

        if redact_type == RedactType.SYNTHETIC:
            canon_key = normalize_entity_key(pii_type, value)
            base_synthetic = synthetic_map[canon_key]
            replacement = _format_synthetic(pii_type, base_synthetic, value)
        else:
            replacement = f"[REDACTED_{pii_type}_{idx}]"

        entities.append(
            PIIEntity(
                type=pii_type,
                original=value,
                replacement=replacement,
                start=start,
                end=end,
                checksum_valid=checksum_valid,
            )
        )
        sanitized = sanitized[:start] + replacement + sanitized[end:]

    entities.reverse()
    if entity_map is not None:
        entity_map.update(synthetic_map)

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return SanitizeResponse(
        sanitized_text=sanitized,
        pii_detected=entities,
        total_entities=len(entities),
        processing_time_ms=round(elapsed_ms, 2),
        redact_type=redact_type.value,
    )


def _get_synthetic(pii_type: str) -> str:
    generators = {
        "CPF": generate_synthetic_cpf,
        "CNPJ": generate_synthetic_cnpj,
        "EMAIL": generate_synthetic_email,
        "PHONE": generate_synthetic_phone,
        "NAME": generate_synthetic_name,
        "MONEY": generate_synthetic_money,
        "BANK_ACCOUNT": generate_synthetic_bank_account,
    }
    gen = generators.get(pii_type)
    return gen() if gen else f"[SYNTHETIC_{pii_type}]"

