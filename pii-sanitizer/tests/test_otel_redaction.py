"""
Test Suite: OpenTelemetry GenAI Privacy Redaction (KAG-T06)
============================================================
Validates compliance under BCB CMN 4893/21 & BCB 85/21:
1. OpenTelemetry Collector Contrib configures attributes/redact_genai processor.
2. Deprecated 'logging' exporter is replaced with 'debug'.
3. 'gen_ai.prompt' and 'gen_ai.completion' are scrubbed to [REDACTED_BY_BCB_COMPLIANCE_POLICY].
4. Operational and FinOps metrics ('gen_ai.usage.*', latencies, model) are 100% preserved.
5. Kong declarative configurations enable bundled 'opentelemetry' plugin.
"""

from pathlib import Path
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OTEL_CONFIG_PATH = REPO_ROOT / "config" / "otel-collector-config.yml"
KONG_OSS_PATH = REPO_ROOT / "config" / "kong.oss.yaml"
KONG_ENTERPRISE_PATH = REPO_ROOT / "config" / "kong.enterprise.yaml"
KONG_DEFAULT_PATH = REPO_ROOT / "config" / "kong.yaml"

REDACTED_TEXT = "[REDACTED_BY_BCB_COMPLIANCE_POLICY]"


def test_otel_collector_config_structure():
    """Verify that otel-collector-config.yml replaces deprecated logging exporter with debug."""
    assert OTEL_CONFIG_PATH.exists(), f"Missing config: {OTEL_CONFIG_PATH}"
    with open(OTEL_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Validate receivers
    assert "receivers" in config
    assert "otlp" in config["receivers"]
    protocols = config["receivers"]["otlp"]["protocols"]
    assert "grpc" in protocols and "http" in protocols

    # Validate deprecated 'logging' exporter is removed and 'debug' is used
    assert "exporters" in config
    assert "logging" not in config["exporters"], "Deprecated 'logging' exporter must not be used"
    assert "debug" in config["exporters"], "Modern 'debug' exporter must be configured"

    # Validate redaction processor exists
    assert "processors" in config
    assert "attributes/redact_genai" in config["processors"]
    proc = config["processors"]["attributes/redact_genai"]
    actions = proc.get("actions", [])
    action_map = {item["key"]: item for item in actions}

    for required_key in ["gen_ai.prompt", "gen_ai.completion", "ai.prompt", "ai.completion"]:
        assert required_key in action_map, f"Missing redaction action for {required_key}"
        assert action_map[required_key]["action"] == "update"
        assert action_map[required_key]["value"] == REDACTED_TEXT

    # Validate traces pipeline wiring
    pipelines = config["service"]["pipelines"]
    assert "traces" in pipelines
    assert "attributes/redact_genai" in pipelines["traces"]["processors"]
    assert "debug" in pipelines["traces"]["exporters"]

    # Validate metrics pipeline preserves operational metrics without prompt redaction
    assert "metrics" in pipelines
    assert "attributes/redact_genai" not in pipelines["metrics"]["processors"]
    assert "debug" in pipelines["metrics"]["exporters"]


@pytest.mark.parametrize("config_path", [KONG_OSS_PATH, KONG_ENTERPRISE_PATH, KONG_DEFAULT_PATH])
def test_kong_declarative_configs_have_opentelemetry(config_path: Path):
    """Verify that Kong declarative configs include the opentelemetry plugin pointing to collector."""
    assert config_path.exists(), f"Missing config: {config_path}"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    services = config.get("services", [])
    assert len(services) > 0, f"No services declared in {config_path.name}"

    service_plugins = services[0].get("plugins", [])
    plugin_names = [p["name"] for p in service_plugins]

    # Verify both the Lua log serializer and the native OTel span exporter are present
    assert "bcb-otel-scrubber" in plugin_names, f"'bcb-otel-scrubber' missing from {config_path.name}"
    assert "opentelemetry" in plugin_names, f"'opentelemetry' missing from {config_path.name}"

    otel_plugin = next(p for p in service_plugins if p["name"] == "opentelemetry")
    assert otel_plugin["config"]["endpoint"] == "http://otel-collector:4318/v1/traces"


def test_otel_span_redaction_simulation():
    """Simulate span redaction processor: redacts prompt/completion payloads while preserving token & latency metrics."""
    # Simulated input span attributes received by collector
    span_attributes = {
        "gen_ai.prompt": "Transfer R$ 50.000,00 from CPF 123.456.789-00 to agency 1234 account 56789-0",
        "gen_ai.completion": "Transfer executed successfully. Transaction ID 987654321.",
        "gen_ai.system": "openai",
        "gen_ai.request.model": "gpt-4o",
        "gen_ai.operation.name": "chat",
        "gen_ai.usage.input_tokens": 85,
        "gen_ai.usage.output_tokens": 22,
        "http.response.status_code": 200,
        "kong.latency": 14.8,
        "upstream.latency": 320.5,
    }

    # Load actual actions from config file
    with open(OTEL_CONFIG_PATH, "r", encoding="utf-8") as f:
        collector_cfg = yaml.safe_load(f)

    actions = collector_cfg["processors"]["attributes/redact_genai"]["actions"]

    # Execute processor transformation on span attributes
    processed_attributes = dict(span_attributes)
    for action in actions:
        key = action["key"]
        act_type = action["action"]
        val = action["value"]
        if act_type == "update" and key in processed_attributes:
            processed_attributes[key] = val

    # Assert privacy redaction
    assert processed_attributes["gen_ai.prompt"] == REDACTED_TEXT
    assert processed_attributes["gen_ai.completion"] == REDACTED_TEXT

    # Assert metric preservation (FinOps & Observability)
    assert processed_attributes["gen_ai.system"] == "openai"
    assert processed_attributes["gen_ai.request.model"] == "gpt-4o"
    assert processed_attributes["gen_ai.operation.name"] == "chat"
    assert processed_attributes["gen_ai.usage.input_tokens"] == 85
    assert processed_attributes["gen_ai.usage.output_tokens"] == 22
    assert processed_attributes["http.response.status_code"] == 200
    assert processed_attributes["kong.latency"] == 14.8
    assert processed_attributes["upstream.latency"] == 320.5
