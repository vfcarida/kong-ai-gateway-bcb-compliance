"""
Prometheus Metrics Registry & Exposition
========================================
Thread-safe metrics collection for PII Sanitizer and Token Vault,
exposing standard Prometheus exposition text format (OpenMetrics).
"""

import threading
from typing import Dict, Tuple


class MetricsRegistry:
    """Thread-safe Prometheus metrics registry for PII Sanitizer microservice."""

    def __init__(self):
        self._lock = threading.Lock()
        self.requests_total: Dict[Tuple[str, int], int] = {}
        self.entities_detected_total: Dict[str, int] = {}
        self.processing_seconds_count: int = 0
        self.processing_seconds_sum: float = 0.0

    def record_request(self, endpoint: str, status_code: int, duration_seconds: float):
        """Records request counter and duration metrics."""
        with self._lock:
            key = (endpoint, status_code)
            self.requests_total[key] = self.requests_total.get(key, 0) + 1
            self.processing_seconds_count += 1
            self.processing_seconds_sum += duration_seconds

    def record_entities(self, entity_counts: Dict[str, int]):
        """Records detected entity count breakdown."""
        with self._lock:
            for etype, count in entity_counts.items():
                self.entities_detected_total[etype] = self.entities_detected_total.get(etype, 0) + count

    def generate_prometheus_text(self, active_vault_sessions: int = 0, total_vault_tokens: int = 0) -> str:
        """Serializes current metrics into the Prometheus 0.0.4 text format."""
        with self._lock:
            lines = [
                "# HELP pii_sanitizer_requests_total Total HTTP requests handled by the PII sanitizer",
                "# TYPE pii_sanitizer_requests_total counter",
            ]
            for (endpoint, code), count in sorted(self.requests_total.items()):
                lines.append(f'pii_sanitizer_requests_total{{endpoint="{endpoint}",status="{code}"}} {count}')

            lines.extend([
                "# HELP pii_sanitizer_entities_detected_total Total PII entities intercepted and redacted",
                "# TYPE pii_sanitizer_entities_detected_total counter",
            ])
            for etype, count in sorted(self.entities_detected_total.items()):
                lines.append(f'pii_sanitizer_entities_detected_total{{type="{etype}"}} {count}')

            lines.extend([
                "# HELP pii_sanitizer_processing_seconds Latency of PII sanitization operations in seconds",
                "# TYPE pii_sanitizer_processing_seconds summary",
                f"pii_sanitizer_processing_seconds_sum {self.processing_seconds_sum:.6f}",
                f"pii_sanitizer_processing_seconds_count {self.processing_seconds_count}",
                "# HELP pii_vault_active_sessions Number of currently active sessions in the token vault",
                "# TYPE pii_vault_active_sessions gauge",
                f"pii_vault_active_sessions {active_vault_sessions}",
                "# HELP pii_vault_stored_tokens Number of token mappings stored across all sessions",
                "# TYPE pii_vault_stored_tokens gauge",
                f"pii_vault_stored_tokens {total_vault_tokens}",
            ])
            return "\n".join(lines) + "\n"

    def reset(self):
        """Resets all metrics counters (primarily for unit tests)."""
        with self._lock:
            self.requests_total.clear()
            self.entities_detected_total.clear()
            self.processing_seconds_count = 0
            self.processing_seconds_sum = 0.0


GLOBAL_METRICS = MetricsRegistry()
