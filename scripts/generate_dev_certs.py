"""
Dev TLS Certificate Generator (SEC-01 / TECH-03)
================================================
Generates ephemeral, self-signed X.509 v3 TLS certificates and RSA private keys
with Subject Alternative Names (SANs) for secure in-transit encryption
between Kong AI Gateway and microservices under BCB CMN 4893/21 compliance.

Pure Python implementation requiring no external openssl binary.
"""

import sys
import os
import argparse
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_dev_tls_certificates(
    output_dir: Path,
    key_filename: str = "dev-key.pem",
    cert_filename: str = "dev-cert.pem",
    common_name: str = "pii-sanitizer",
    dns_sans: list = None,
    ip_sans: list = None,
    validity_days: int = 365,
    key_size: int = 2048,
) -> tuple:
    """
    Generates an RSA private key and self-signed X.509 certificate with SANs.

    Returns:
        tuple: (key_path, cert_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    key_path = output_dir / key_filename
    cert_path = output_dir / cert_filename

    # Default SANs covering internal Docker network and local testing
    if dns_sans is None:
        dns_sans = ["localhost", "pii-sanitizer", "kong-gateway-oss", "kong-gateway-enterprise"]
    if ip_sans is None:
        ip_sans = ["127.0.0.1", "::1"]

    # 1. Generate RSA Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Build Subject and Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "DF"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kong AI Gateway BCB Compliance"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DevSecOps"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # 3. Build SANs
    san_entries = []
    for d in dns_sans:
        san_entries.append(x509.DNSName(d))
    for ip in ip_sans:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    )

    # 4. Self-sign certificate using SHA-256
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    # 5. Serialize and write Private Key
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 6. Serialize and write Certificate
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path


def verify_certificate(cert_path: Path) -> dict:
    """Reads and parses an X.509 certificate to verify validity and extensions."""
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate not found at: {cert_path}")

    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data)

    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    is_valid_time = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "is_valid_time": is_valid_time,
        "sans": sans,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate ephemeral self-signed dev TLS certificates for Kong AI Gateway & PII Sanitizer."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(Path(__file__).resolve().parent.parent / "pii-sanitizer" / "certs"),
        help="Directory where dev-key.pem and dev-cert.pem will be saved.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify the certificate at output-dir/dev-cert.pem without regenerating.",
    )

    args = parser.parse_args()
    out_dir = Path(args.output_dir)

    if args.verify:
        cert_file = out_dir / "dev-cert.pem"
        print(f"Verifying TLS certificate: {cert_file}")
        info = verify_certificate(cert_file)
        print("Certificate Details:")
        for k, v in info.items():
            print(f"  {k}: {v}")
        if info["is_valid_time"]:
            print("Status: VALID")
            sys.exit(0)
        else:
            print("Status: EXPIRED OR NOT YET VALID")
            sys.exit(1)

    print(f"Generating new dev TLS certificates in: {out_dir}")
    key_path, cert_path = generate_dev_tls_certificates(out_dir, validity_days=args.days)
    print(f"  Private Key: {key_path}")
    print(f"  Certificate: {cert_path}")

    info = verify_certificate(cert_path)
    print("Verification:")
    print(f"  Subject: {info['subject']}")
    print(f"  SANs: {', '.join(info['sans'])}")
    print(f"  Valid until: {info['not_after']}")
    print("Dev TLS generation completed successfully.")


if __name__ == "__main__":
    main()
