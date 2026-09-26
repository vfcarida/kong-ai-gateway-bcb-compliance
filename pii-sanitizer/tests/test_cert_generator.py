"""
Pytest Suite — TLS Dev Certificate Generation & Validation (SEC-01 / TECH-03)
==============================================================================
Validates cross-platform ephemeral TLS certificate generation, X.509 v3
Subject Alternative Names (SANs), key generation, and certificate verification.
"""

import sys
import os
from pathlib import Path
import pytest

# Ensure scripts directory is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.generate_dev_certs import generate_dev_tls_certificates, verify_certificate


def test_generate_and_verify_certificates(tmp_path):
    """Verifies end-to-end generation and parsing of dev TLS certificates."""
    key_file, cert_file = generate_dev_tls_certificates(
        output_dir=tmp_path,
        validity_days=30,
        dns_sans=["custom-domain.local", "sanitizer-stage"],
        ip_sans=["10.0.0.1"],
    )

    assert key_file.exists()
    assert cert_file.exists()

    # Check key contents
    key_text = key_file.read_text(encoding="utf-8")
    assert "BEGIN RSA PRIVATE KEY" in key_text

    # Check cert contents
    cert_text = cert_file.read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in cert_text

    # Verify certificate attributes
    info = verify_certificate(cert_file)
    assert info["is_valid_time"] is True
    assert "CN=pii-sanitizer" in info["subject"]
    assert "custom-domain.local" in info["sans"]
    assert "sanitizer-stage" in info["sans"]
    assert "10.0.0.1" in info["sans"]


def test_verify_non_existent_certificate_raises(tmp_path):
    """Verifies that attempting to verify a missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        verify_certificate(tmp_path / "non-existent.pem")
