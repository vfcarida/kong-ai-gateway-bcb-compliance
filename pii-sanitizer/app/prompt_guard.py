"""
AI Prompt Injection & Jailbreak Guardrail Engine (OWASP LLM01:2025)
==================================================================
Heuristic and pattern-based guardrail scanner detecting prompt injections,
jailbreaks (DAN, Developer Mode), delimiter spoofing, and system prompt
exfiltration attempts under BCB CMN 4893/21 and BCB 85/21.
"""

import re
from typing import List, Dict, Tuple, Optional

from app.schemas import PromptGuardResult


# ── Guardrail Pattern Definitions ─────────────────────────────────────────────

GUARDRAIL_RULES: List[Tuple[str, str, re.Pattern]] = [
    # 1. Direct Instruction Override
    (
        "DIRECT_INSTRUCTION_OVERRIDE",
        "instruction_override_disregard_previous",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[\s\w,]{1,40}\b(?:all\s+)?(?:previous|prior|above|initial|preceding)\b[\s\w,]{0,20}\b(?:instructions|rules|directives|prompts|guidelines|constraints)\b"
        ),
    ),
    (
        "DIRECT_INSTRUCTION_OVERRIDE",
        "instruction_override_system_reset",
        re.compile(
            r"(?i)\b(?:new\s+system\s+instructions?|system\s+override(?:\s+mode)?|reset\s+(?:all\s+)?instructions)\b"
        ),
    ),
    # 2. Jailbreak Persona Adoption
    (
        "JAILBREAK_PERSONA",
        "persona_jailbreak_dan_mode",
        re.compile(
            r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\b[\s\w,]{1,30}\b(?:dan|unrestricted|jailbroken|evil|unfiltered|aim|stan|chaos)\b"
        ),
    ),
    (
        "JAILBREAK_PERSONA",
        "persona_jailbreak_unrestricted_mode",
        re.compile(
            r"(?i)\b(?:do\s+anything\s+now|jailbreak\s+(?:mode|prompt)|developer\s+mode\s+(?:enabled|active)|bypass\s+ethical\s+guidelines)\b"
        ),
    ),
    (
        "JAILBREAK_PERSONA",
        "persona_unconditional_compliance",
        re.compile(
            r"(?i)\b(?:always\s+comply\s+without\s+refusal|never\s+say\s+no|ignore\s+(?:all\s+)?content\s+policies)\b"
        ),
    ),
    # 3. System Prompt & Instruction Leakage
    (
        "SYSTEM_PROMPT_LEAKAGE",
        "leak_system_instructions",
        re.compile(
            r"(?i)\b(?:output|repeat|print|reveal|show|display|leak)\b[\s\w,]{1,40}\b(?:your\s+)?(?:system\s+(?:prompt|instructions?|message)|initial\s+(?:prompt|instructions?)|core\s+directives?)\b"
        ),
    ),
    (
        "SYSTEM_PROMPT_LEAKAGE",
        "leak_what_are_initial_rules",
        re.compile(
            r"(?i)\b(?:what\s+(?:were|are)\s+your\s+(?:initial\s+)?(?:system\s+)?(?:instructions?|rules|prompt))\b"
        ),
    ),
    # 4. Delimiter & Role Spoofing
    (
        "DELIMITER_SPOOFING",
        "delimiter_role_impersonation",
        re.compile(
            r"(?:<\|im_start\|>system|<\|im_end\|>|\[SYSTEM(?:_PROMPT)?\]|###\s*Instruction:|<system>|\[ADMIN\])"
        ),
    ),
    (
        "DELIMITER_SPOOFING",
        "simulated_system_turn",
        re.compile(
            r"(?i)\b(?:system:\s*you\s+are|system:\s*disregard|system:\s*override)\b"
        ),
    ),
]


def scan_prompt_injection(text: str) -> PromptGuardResult:
    """
    Evaluates input text for prompt injection, jailbreak attempts, and system leakage.
    Returns structured PromptGuardResult with risk classification and matched rules.
    """
    if not text or not text.strip():
        return PromptGuardResult(flagged=False, risk_score=0.0)

    matched_categories = set()
    matched_rule_names = []

    for category, rule_name, pattern in GUARDRAIL_RULES:
        if pattern.search(text):
            matched_categories.add(category)
            matched_rule_names.append(rule_name)

    if not matched_rule_names:
        return PromptGuardResult(
            flagged=False,
            risk_score=0.0,
            threat_categories=[],
            matched_rules=[],
        )

    # Score calculation: 1 rule = 0.85, 2+ rules = 1.0 (deterministic upper bound)
    score = 1.0 if len(matched_rule_names) >= 2 else 0.85

    return PromptGuardResult(
        flagged=True,
        risk_score=score,
        threat_categories=sorted(list(matched_categories)),
        matched_rules=matched_rule_names,
    )
