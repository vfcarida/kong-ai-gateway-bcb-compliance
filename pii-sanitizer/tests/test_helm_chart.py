"""
Pytest Suite — Helm Chart Validation (FEAT-06)
==============================================
Validates the Helm chart structure, metadata, values.yaml syntax,
and template definitions under charts/kong-ai-gateway-bcb-compliance/.
"""

from pathlib import Path
import yaml
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHART_DIR = REPO_ROOT / "charts" / "kong-ai-gateway-bcb-compliance"


def test_helm_chart_files_exist():
    assert CHART_DIR.exists()
    assert (CHART_DIR / "Chart.yaml").exists()
    assert (CHART_DIR / "values.yaml").exists()
    assert (CHART_DIR / "templates" / "_helpers.tpl").exists()
    assert (CHART_DIR / "templates" / "deployment-sanitizer.yaml").exists()
    assert (CHART_DIR / "templates" / "service-sanitizer.yaml").exists()
    assert (CHART_DIR / "templates" / "kongplugin.yaml").exists()
    assert (CHART_DIR / "templates" / "ingress.yaml").exists()
    assert (CHART_DIR / "templates" / "otel-collector.yaml").exists()


def test_chart_yaml_metadata():
    with open(CHART_DIR / "Chart.yaml", "r", encoding="utf-8") as f:
        meta = yaml.safe_load(f)

    assert meta["apiVersion"] == "v2"
    assert meta["name"] == "kong-ai-gateway-bcb-compliance"
    assert "version" in meta
    assert "appVersion" in meta
    assert "maintainers" in meta
    assert len(meta["maintainers"]) > 0


def test_values_yaml_structure():
    with open(CHART_DIR / "values.yaml", "r", encoding="utf-8") as f:
        vals = yaml.safe_load(f)

    assert vals["replicaCount"] >= 1
    assert "image" in vals
    assert "resources" in vals
    assert "podSecurityContext" in vals
    assert vals["podSecurityContext"]["runAsNonRoot"] is True

    # KongPlugins
    assert "kongPlugins" in vals
    assert vals["kongPlugins"]["piiSanitizer"]["enabled"] is True
    assert vals["kongPlugins"]["piiSanitizer"]["failOpen"] is False
    assert vals["kongPlugins"]["otelScrubber"]["enabled"] is True

    # Ingress
    assert vals["ingress"]["enabled"] is True
    assert vals["ingress"]["path"] == "/llm-proxy"
