"""
Test Suite: Admin Plane & TLS Hardening Verification (KAG-T07)
==============================================================
Validates compliance under BCB CMN 4893/21 & BCB 85/21:
1. Kong Admin plane (ports 8001, 8444, 8002) is unexposed to the host and bound to loopback.
2. Only data plane proxy ports (8000, 8443) are exposed on host.
3. Kong <-> Sanitizer communication is TLS encrypted (https://pii-sanitizer:8443).
4. PII Sanitizer terminates TLS with valid certificates and exposes HTTPS port 8443.
5. bcb-pii-sanitizer schema and declarative configs enforce HTTPS and ssl_verify option.
"""

from pathlib import Path
import ssl
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
KONG_OSS_PATH = REPO_ROOT / "config" / "kong.oss.yaml"
KONG_ENTERPRISE_PATH = REPO_ROOT / "config" / "kong.enterprise.yaml"
KONG_DEFAULT_PATH = REPO_ROOT / "config" / "kong.yaml"
SCHEMA_LUA_PATH = REPO_ROOT / "plugins" / "bcb-pii-sanitizer" / "kong" / "plugins" / "bcb-pii-sanitizer" / "schema.lua"
DEV_CERT_PATH = REPO_ROOT / "pii-sanitizer" / "certs" / "dev-cert.pem"
DEV_KEY_PATH = REPO_ROOT / "pii-sanitizer" / "certs" / "dev-key.pem"


def test_docker_compose_admin_plane_hardening():
    """Verify Admin API ports are completely removed from host exposure and bound to 127.0.0.1."""
    assert COMPOSE_PATH.exists()
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})

    for gateway_name in ["kong-gateway-oss", "kong-gateway-enterprise"]:
        assert gateway_name in services, f"Missing service {gateway_name}"
        gw = services[gateway_name]

        # Verify ports published to host
        ports = [str(p) for p in gw.get("ports", [])]
        for prohibited_port in ["8001", "8444", "8002"]:
            for p in ports:
                assert prohibited_port not in p, (
                    f"Vulnerability F-09: Prohibited Admin/GUI port {prohibited_port} "
                    f"is exposed to host in {gateway_name}: {p}"
                )

        # Ensure proxy ports remain published
        assert any("8000:8000" in p for p in ports), f"Missing proxy port 8000 in {gateway_name}"
        assert any("8443:8443" in p for p in ports), f"Missing proxy port 8443 in {gateway_name}"

        # Verify listening address bindings are restricted to loopback
        env = gw.get("environment", {})
        admin_listen = env.get("KONG_ADMIN_LISTEN", "")
        admin_gui_listen = env.get("KONG_ADMIN_GUI_LISTEN", "")

        assert "127.0.0.1:8001" in admin_listen, f"Admin listen must bind to 127.0.0.1 in {gateway_name}"
        assert "0.0.0.0:8001" not in admin_listen, f"Admin listen must NOT bind to 0.0.0.0 in {gateway_name}"
        assert "127.0.0.1:8002" in admin_gui_listen, f"Admin GUI listen must bind to 127.0.0.1 in {gateway_name}"
        assert "0.0.0.0:8002" not in admin_gui_listen, f"Admin GUI listen must NOT bind to 0.0.0.0 in {gateway_name}"


def test_docker_compose_pii_sanitizer_tls_config():
    """Verify pii-sanitizer terminates TLS on port 8443."""
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    sanitizer = compose["services"]["pii-sanitizer"]
    env = dict(item.split("=", 1) for item in sanitizer.get("environment", []) if "=" in item)

    assert env.get("PORT") == "8443", f"Expected PORT=8443, got {env.get('PORT')}"
    assert "dev-key.pem" in env.get("SSL_KEYFILE", "")
    assert "dev-cert.pem" in env.get("SSL_CERTFILE", "")

    # Host port 8088 maps to container 8443
    ports = [str(p) for p in sanitizer.get("ports", [])]
    assert any("8088:8443" in p for p in ports), f"Expected 8088:8443 port mapping, got {ports}"

    # Healthcheck must use HTTPS
    healthcheck = sanitizer.get("healthcheck", {}).get("test", [])
    cmd_str = " ".join(healthcheck)
    assert "https://localhost:8443/health" in cmd_str, "Sanitizer healthcheck must query HTTPS endpoint"


@pytest.mark.parametrize("config_path", [KONG_OSS_PATH, KONG_ENTERPRISE_PATH, KONG_DEFAULT_PATH])
def test_kong_declarative_configs_use_https(config_path: Path):
    """Verify Kong declarative configs use HTTPS for both llm-gateway-service and bcb-pii-sanitizer."""
    assert config_path.exists()
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    service = config["services"][0]
    assert service["url"].startswith("https://"), f"Service upstream URL must be HTTPS in {config_path.name}"
    assert service.get("protocol") == "https", f"Service protocol must be https in {config_path.name}"

    plugins = service.get("plugins", [])
    sanitizer_plugin = next(p for p in plugins if p["name"] == "bcb-pii-sanitizer")
    sanitizer_url = sanitizer_plugin["config"]["sanitizer_url"]

    assert sanitizer_url.startswith("https://"), (
        f"Vulnerability F-10: PII sanitizer URL must be HTTPS in {config_path.name}, got {sanitizer_url}"
    )
    assert "8443" in sanitizer_url, f"Expected port 8443 in {sanitizer_url}"
    assert "ssl_verify" in sanitizer_plugin["config"]


def test_dev_certificates_exist_and_valid():
    """Verify dev TLS certificates exist and can be loaded by Python ssl module."""
    assert DEV_CERT_PATH.exists(), f"Missing dev cert: {DEV_CERT_PATH}"
    assert DEV_KEY_PATH.exists(), f"Missing dev key: {DEV_KEY_PATH}"

    cert_text = DEV_CERT_PATH.read_text(encoding="utf-8")
    key_text = DEV_KEY_PATH.read_text(encoding="utf-8")

    assert "-----BEGIN CERTIFICATE-----" in cert_text
    assert "-----END CERTIFICATE-----" in cert_text
    assert "-----BEGIN PRIVATE KEY-----" in key_text or "-----BEGIN RSA PRIVATE KEY-----" in key_text

    # Test loading in SSLContext
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(DEV_CERT_PATH), keyfile=str(DEV_KEY_PATH))
    assert ctx is not None


def test_schema_lua_includes_tls_support():
    """Verify bcb-pii-sanitizer schema.lua includes ssl_verify and HTTPS default."""
    assert SCHEMA_LUA_PATH.exists()
    content = SCHEMA_LUA_PATH.read_text(encoding="utf-8")

    assert "ssl_verify" in content
    assert "https://pii-sanitizer:8443/sanitize" in content
