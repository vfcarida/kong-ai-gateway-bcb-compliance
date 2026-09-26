"""
Pytest Suite — Kubernetes Manifests & KongPlugin CRD Validation (FEAT-04)
==========================================================================
Verifies that Kubernetes manifests in k8s/ are syntactically valid YAML,
contain all expected resources, and follow security hardening standards.
"""

from pathlib import Path
import yaml
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
K8S_DIR = REPO_ROOT / "k8s"


def test_k8s_directory_exists():
    assert K8S_DIR.exists()
    assert (K8S_DIR / "kustomization.yaml").exists()


def test_all_k8s_yaml_valid():
    yaml_files = list(K8S_DIR.glob("*.yaml"))
    assert len(yaml_files) >= 5

    kinds = set()
    for yf in yaml_files:
        with open(yf, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and "kind" in doc:
                    kinds.add(doc["kind"])

    # Ensure all expected Kubernetes kinds are defined
    assert "Namespace" in kinds
    assert "KongPlugin" in kinds
    assert "Deployment" in kinds
    assert "Service" in kinds
    assert "Ingress" in kinds
    assert "ConfigMap" in kinds


def test_kong_plugins_crd_configuration():
    plugin_file = K8S_DIR / "kong-plugins.yaml"
    with open(plugin_file, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    plugins = {doc["metadata"]["name"]: doc for doc in docs if doc and doc.get("kind") == "KongPlugin"}
    assert "bcb-pii-sanitizer" in plugins
    assert "bcb-otel-scrubber" in plugins

    sanitizer_conf = plugins["bcb-pii-sanitizer"]["config"]
    assert sanitizer_conf["fail_open"] is False
    assert sanitizer_conf["ssl_verify"] is True
    assert "sanitizer_url" in sanitizer_conf

    scrubber_conf = plugins["bcb-otel-scrubber"]["config"]
    assert scrubber_conf["preserve_finops_metrics"] is True
    assert "[REDACTED_BY_BCB_SCRUBBER]" in scrubber_conf["log_redaction_marker"]


def test_pii_sanitizer_security_context():
    dep_file = K8S_DIR / "pii-sanitizer.yaml"
    with open(dep_file, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    dep = next(d for d in docs if d and d.get("kind") == "Deployment")
    pod_sec = dep["spec"]["template"]["spec"]["securityContext"]
    assert pod_sec.get("runAsNonRoot") is True

    container_sec = dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert container_sec.get("allowPrivilegeEscalation") is False
    assert "ALL" in container_sec.get("capabilities", {}).get("drop", [])
