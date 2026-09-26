"""
AI Engineering Evaluation Benchmark — Brazilian Financial PII Detection
========================================================================
Quantitative evaluation framework for PII detection and redaction accuracy
in Brazilian banking conversational contexts.

Calculates:
- Entity-Level True Positives (TP), False Positives (FP), False Negatives (FN)
- Precision, Recall, and F1-score across all PII classes
- Micro- and Macro-averaged benchmarks
- False Negative Rate (FNR / Leakage Rate)
- Zero-Leakage Guarantee for regulated national identifiers (CPF, CNPJ)
- False-Positive Resistance against negative control adversarial samples
- P95 Latency SLA evaluation (< 15ms budget)
"""

import sys
import os
import time
import pytest
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Ensure app package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.pii_engine import detect_and_sanitize, normalize_entity_key
from app.schemas import RedactType, PIIEntity


@dataclass
class GroundTruthEntity:
    entity_type: str
    value: str


@dataclass
class BenchmarkSample:
    sample_id: str
    text: str
    expected_entities: List[GroundTruthEntity] = field(default_factory=list)
    is_negative_control: bool = False


# ── Benchmark Evaluation Dataset (Realistic Brazilian Banking Scenarios) ────────

BENCHMARK_DATASET: List[BenchmarkSample] = [
    # Scenario 1: Pix Transfer with Name, Money, and Bank Account
    BenchmarkSample(
        sample_id="banking_pix_01",
        text="Olá, meu nome é Carlos Eduardo da Silva. Gostaria de transferir R$ 1.500,00 para a conta agência 1234 conta 56789-0 do meu sócio.",
        expected_entities=[
            GroundTruthEntity("NAME", "Carlos Eduardo da Silva"),
            GroundTruthEntity("MONEY", "R$ 1.500,00"),
            GroundTruthEntity("BANK_ACCOUNT", "agência 1234 conta 56789-0"),
        ],
    ),
    # Scenario 2: KYC Registration with Formatted CPF, Email, and Phone
    BenchmarkSample(
        sample_id="banking_kyc_02",
        text="Preciso atualizar meu cadastro. Meu CPF é 123.456.789-09 e meu e-mail de contato é carlos.silva@empresa.com.br. Meu telefone celular é (11) 98765-4321.",
        expected_entities=[
            GroundTruthEntity("CPF", "123.456.789-09"),
            GroundTruthEntity("EMAIL", "carlos.silva@empresa.com.br"),
            GroundTruthEntity("PHONE", "(11) 98765-4321"),
        ],
    ),
    # Scenario 3: Corporate Credit Inquiry with CNPJ and High Value Money
    BenchmarkSample(
        sample_id="banking_corporate_03",
        text="A empresa Alpha Soluções Financeiras com CNPJ 11.222.333/0001-81 fez uma solicitação de empréstimo no valor de R$ 75.000,00.",
        expected_entities=[
            GroundTruthEntity("NAME", "Alpha Soluções Financeiras"),
            GroundTruthEntity("CNPJ", "11.222.333/0001-81"),
            GroundTruthEntity("MONEY", "R$ 75.000,00"),
        ],
    ),
    # Scenario 4: Raw CPF Checksum-Validated Key with Name and Small Pix
    BenchmarkSample(
        sample_id="banking_raw_cpf_pix_04",
        text="Por favor confirme o Pix de R$ 420,50 para a chave 12345678909 cadastrada em nome de Roberto Alves.",
        expected_entities=[
            GroundTruthEntity("MONEY", "R$ 420,50"),
            GroundTruthEntity("CPF", "12345678909"),
            GroundTruthEntity("NAME", "Roberto Alves"),
        ],
    ),
    # Scenario 5: Security Dispute with Email and Landline Phone
    BenchmarkSample(
        sample_id="banking_dispute_05",
        text="Recebi um e-mail de cobranca@banco-digital.com e gostaria de verificar se é legítimo. Meu telefone fixo é (21) 2555-0199.",
        expected_entities=[
            GroundTruthEntity("EMAIL", "cobranca@banco-digital.com"),
            GroundTruthEntity("PHONE", "(21) 2555-0199"),
        ],
    ),
    # Scenario 6: Bank Account Compound Details & Card Replacement
    BenchmarkSample(
        sample_id="banking_card_account_06",
        text="Solicito segunda via do cartão da conta c/c 9876-5 agência 4321 em nome de Juliana Ferreira Lima.",
        expected_entities=[
            GroundTruthEntity("BANK_ACCOUNT", "c/c 9876-5 agência 4321"),
            GroundTruthEntity("NAME", "Juliana Ferreira Lima"),
        ],
    ),
    # Scenario 7: Raw CNPJ with Formatted Bank Account & Deposit
    BenchmarkSample(
        sample_id="banking_raw_cnpj_07",
        text="Depósito identificado de R$ 12.350,00 na agência 0001 c/c 12345-6 para o fornecedor CNPJ 11222333000181.",
        expected_entities=[
            GroundTruthEntity("MONEY", "R$ 12.350,00"),
            GroundTruthEntity("BANK_ACCOUNT", "agência 0001 c/c 12345-6"),
            GroundTruthEntity("CNPJ", "11222333000181"),
        ],
    ),
    # Scenario 8: Customer Support Self-Identification
    BenchmarkSample(
        sample_id="banking_identity_08",
        text="Me chamo Marcos Vinicius Santos e meu e-mail é marcos.santos@fintech.io.",
        expected_entities=[
            GroundTruthEntity("NAME", "Marcos Vinicius Santos"),
            GroundTruthEntity("EMAIL", "marcos.santos@fintech.io"),
        ],
    ),
    # Scenario 9: Unformatted Phone and Support Email
    BenchmarkSample(
        sample_id="banking_contact_09",
        text="Envie o comprovante para suporte@pagamentos.com.br ou ligue para 11988887777.",
        expected_entities=[
            GroundTruthEntity("EMAIL", "suporte@pagamentos.com.br"),
            GroundTruthEntity("PHONE", "11988887777"),
        ],
    ),
    # Scenario 10: Automatic Debit with Account and Cents
    BenchmarkSample(
        sample_id="banking_debit_10",
        text="Autorizo débito de R$ 99,90 da conta corrente ag 3456 conta 87654-3.",
        expected_entities=[
            GroundTruthEntity("MONEY", "R$ 99,90"),
            GroundTruthEntity("BANK_ACCOUNT", "ag 3456 conta 87654-3"),
        ],
    ),
    # Scenario 11: Credit Card Fraud Dispute with Formatted Card
    BenchmarkSample(
        sample_id="banking_credit_card_dispute_11",
        text="Favor estornar compra no cartao 5555 5555 5555 4444 cobrada indevidamente.",
        expected_entities=[
            GroundTruthEntity("CREDIT_CARD", "5555 5555 5555 4444"),
        ],
    ),
    # Scenario 12: Multi-PII Verification with Raw Card Number and Formatted CPF
    BenchmarkSample(
        sample_id="banking_raw_card_kyc_12",
        text="Confirmacao de seguranca: cartao titular 5555555555554444 e CPF 123.456.789-09.",
        expected_entities=[
            GroundTruthEntity("CREDIT_CARD", "5555555555554444"),
            GroundTruthEntity("CPF", "123.456.789-09"),
        ],
    ),
    # ── Negative Controls (Adversarial Non-PII to test False-Positive Resistance) ─
    BenchmarkSample(
        sample_id="neg_ctrl_order_and_tracking",
        text="O pedido #98765432101 foi despachado via código de rastreamento BR12345678901234. Favor verificar o status na central.",
        expected_entities=[],
        is_negative_control=True,
    ),
    BenchmarkSample(
        sample_id="neg_ctrl_sfn_bcb_regulation",
        text="O protocolo de atendimento do Sistema Financeiro Nacional é 20260925-883920. O Banco Central do Brasil regulamenta as operações conforme a Resolução CMN 4893.",
        expected_entities=[],
        is_negative_control=True,
    ),
    BenchmarkSample(
        sample_id="neg_ctrl_architecture_terms",
        text="A arquitetura do Kong Gateway processa requisições via Amazon Bedrock com latência inferior a 10 milissegundos sem retenção de dados.",
        expected_entities=[],
        is_negative_control=True,
    ),
    BenchmarkSample(
        sample_id="neg_ctrl_financial_vocabulary",
        text="Qual o saldo da minha conta e como posso agendar um pagamento via pix ou ted no extrato mensal?",
        expected_entities=[],
        is_negative_control=True,
    ),
    BenchmarkSample(
        sample_id="neg_ctrl_uuid_and_hashes",
        text="O correlation ID da requisição é 4a8e63b2-9d71-482a-bc93-61d0f507b992 e o commit é e353924e1ce7ab22a7e8cbf10f0e2b639b9f64aa.",
        expected_entities=[],
        is_negative_control=True,
    ),
    BenchmarkSample(
        sample_id="neg_ctrl_16_digit_barcode",
        text="O codigo de barras da guia de recolhimento e 1234567890123456 para pagamento no terminal.",
        expected_entities=[],
        is_negative_control=True,
    ),
]


# ── Evaluation Engine ─────────────────────────────────────────────────────────


@dataclass
class ClassMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def fnr(self) -> float:
        """False Negative Rate (Leakage Rate)."""
        return self.fn / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0


def evaluate_benchmark(dataset: List[BenchmarkSample]) -> Tuple[Dict[str, ClassMetrics], ClassMetrics, List[float]]:
    """Evaluates the dataset against the PII Sanitizer engine.
    
    Returns:
        per_class: Dictionary of ClassMetrics per entity type
        micro_aggregate: Aggregated ClassMetrics across all classes
        latencies: List of per-sample processing latency in milliseconds
    """
    per_class: Dict[str, ClassMetrics] = {}
    micro_aggregate = ClassMetrics()
    latencies: List[float] = []

    # Warmup invocation to initialize regex engine caches and Python module internals
    detect_and_sanitize("Warmup prompt with R$ 10,00 and CPF 123.456.789-00", redact_type=RedactType.PLACEHOLDER)

    for sample in dataset:
        t0 = time.perf_counter()
        response = detect_and_sanitize(sample.text, redact_type=RedactType.PLACEHOLDER)
        latencies.append((time.perf_counter() - t0) * 1000)

        predicted_entities = list(response.pii_detected)
        expected_entities = list(sample.expected_entities)

        # Match predicted entities to ground truth
        matched_expected_indices = set()
        matched_predicted_indices = set()

        for p_idx, pred in enumerate(predicted_entities):
            pred_key = normalize_entity_key(pred.type, pred.original)
            best_match_idx = None

            for e_idx, exp in enumerate(expected_entities):
                if e_idx in matched_expected_indices:
                    continue
                if pred.type == exp.entity_type:
                    exp_key = normalize_entity_key(exp.entity_type, exp.value)
                    if pred_key == exp_key or exp.value in pred.original or pred.original in exp.value:
                        best_match_idx = e_idx
                        break

            if best_match_idx is not None:
                matched_expected_indices.add(best_match_idx)
                matched_predicted_indices.add(p_idx)
                metrics = per_class.setdefault(pred.type, ClassMetrics())
                metrics.tp += 1
                micro_aggregate.tp += 1

        # Unmatched predicted entities are False Positives
        for p_idx, pred in enumerate(predicted_entities):
            if p_idx not in matched_predicted_indices:
                metrics = per_class.setdefault(pred.type, ClassMetrics())
                metrics.fp += 1
                micro_aggregate.fp += 1

        # Unmatched expected entities are False Negatives (Data Leakages)
        for e_idx, exp in enumerate(expected_entities):
            if e_idx not in matched_expected_indices:
                metrics = per_class.setdefault(exp.entity_type, ClassMetrics())
                metrics.fn += 1
                micro_aggregate.fn += 1

    return per_class, micro_aggregate, latencies


# ── Benchmark Test Assertions ──────────────────────────────────────────────────


def test_pii_evaluation_metrics_benchmark():
    """Validates that detection precision, recall, and F1 exceed production thresholds."""
    per_class, micro, latencies = evaluate_benchmark(BENCHMARK_DATASET)

    # 1. Overall Aggregated Benchmarks
    print("\n" + "=" * 65)
    print("AI DLP QUANTITATIVE EVALUATION BENCHMARK REPORT")
    print("=" * 65)
    print(f"{'Entity Class':<15} {'TP':<5} {'FP':<5} {'FN':<5} {'Prec':<8} {'Rec':<8} {'F1':<8} {'FNR (Leak)':<10}")
    print("-" * 65)

    for cls_name, m in sorted(per_class.items()):
        print(
            f"{cls_name:<15} {m.tp:<5} {m.fp:<5} {m.fn:<5} "
            f"{m.precision * 100:>6.1f}% {m.recall * 100:>6.1f}% {m.f1:>7.3f} "
            f"{m.fnr * 100:>8.2f}%"
        )
    print("-" * 65)
    print(
        f"{'MICRO TOTAL':<15} {micro.tp:<5} {micro.fp:<5} {micro.fn:<5} "
        f"{micro.precision * 100:>6.1f}% {micro.recall * 100:>6.1f}% {micro.f1:>7.3f} "
        f"{micro.fnr * 100:>8.2f}%"
    )
    print("=" * 65)

    # Assertions on Micro Metrics
    assert micro.recall >= 0.95, f"Aggregated Recall {micro.recall * 100:.1f}% below target threshold 95.0%"
    assert micro.precision >= 0.90, f"Aggregated Precision {micro.precision * 100:.1f}% below target threshold 90.0%"
    assert micro.f1 >= 0.92, f"Aggregated F1-Score {micro.f1:.3f} below target threshold 0.92"


def test_zero_leakage_guarantee_regulated_identifiers():
    """Asserts Zero Leakage (FNR = 0.00%, FN = 0) on regulated identifiers (CPF, CNPJ, CREDIT_CARD)."""
    per_class, _, _ = evaluate_benchmark(BENCHMARK_DATASET)

    # Regulated Identifiers must have ZERO False Negatives
    for identifier in ("CPF", "CNPJ", "CREDIT_CARD"):
        assert identifier in per_class, f"Identifier {identifier} not evaluated in benchmark"
        m = per_class[identifier]
        assert m.fn == 0, f"DATA LEAKAGE DETECTED: {identifier} had {m.fn} false negatives! FNR={m.fnr * 100:.2f}%"
        assert m.recall == 1.0, f"Zero-leakage guarantee violated: {identifier} recall is {m.recall * 100:.1f}%, expected 100.0%"


def test_negative_control_false_positive_resistance():
    """Asserts that adversarial negative controls produce zero false positive entity detections."""
    negative_samples = [s for s in BENCHMARK_DATASET if s.is_negative_control]
    assert len(negative_samples) >= 5, "Benchmark must include at least 5 negative control scenarios"

    _, micro, _ = evaluate_benchmark(negative_samples)
    assert micro.fp == 0, f"False Positive detected on negative controls: {micro.fp} spurious entities identified"
    assert micro.tp == 0
    assert micro.fn == 0


def test_latency_budget_benchmark():
    """Asserts that P95 processing latency remains strictly within the 15ms budget."""
    _, _, latencies = evaluate_benchmark(BENCHMARK_DATASET)
    sorted_latencies = sorted(latencies)
    p95_index = int(len(sorted_latencies) * 0.95)
    p95_latency = sorted_latencies[p95_index]
    avg_latency = sum(latencies) / len(latencies)

    print(f"\nLatency Benchmark: Avg={avg_latency:.2f}ms, P95={p95_latency:.2f}ms (Max SLA: 15.0ms)")
    assert p95_latency < 15.0, f"P95 latency {p95_latency:.2f}ms exceeded 15.0ms SLA budget"
