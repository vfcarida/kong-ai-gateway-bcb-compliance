# Security Policy

## 🛡️ Supported Versions

We provide security updates and patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

---

## 🔒 Reporting a Vulnerability

We take the security of financial infrastructure and data protection controls seriously. If you discover a security vulnerability or regulatory compliance bypass within this repository, please report it responsibly.

### How to Report
- **Email**: Send vulnerability reports directly to `vfcarida@gmail.com` with the subject line `[SECURITY VULNERABILITY] kong-ai-gateway-bcb-compliance`.
- **Details to Include**:
  - Description of the vulnerability or bypass mechanism.
  - Steps to reproduce, including sample request payloads and curl commands.
  - Affected components (`bcb-pii-sanitizer`, `bcb-otel-scrubber`, `pii-sanitizer`, `otel-collector`).
  - Assessment of impact under Resolution CMN nº 4.893/2021 or BCB nº 85/2021.

### Our Commitment
- We will acknowledge receipt of your vulnerability report within 48 hours.
- We will provide a triage assessment and target remediation timeline within 5 business days.
- We ask that you maintain confidentiality until an official patch and advisory are released.

---

## 🏛️ Regulatory Scope & Threat Model

This repository provides **technical control building blocks** designed to support institutional compliance efforts under:
- **Resolução CMN nº 4.893/2021** (as amended by **CMN nº 5.274/2025**)
- **Resolução BCB nº 85/2021**
- **OWASP Top 10 for LLM Applications (2025)**

### Threat Model Boundaries
1. **Perimeter Ingress PII Sanitization**: Reduces the risk of inadvertent transmission of Brazilian CPFs, CNPJs, bank account numbers, and monetary amounts to third-party model providers.
2. **Telemetry Privacy Protection**: Strips raw prompt and completion content from APM traces and gateway logs while preserving operational token counters.
3. **Hardened Admin Plane**: Binds management APIs to loopback (`127.0.0.1`) to prevent unauthorized remote reconfiguration.

---

## 🔑 Cryptographic Keys, TLS Certificates & Secret Management

### 1. Ephemeral Local Development Certificates
For local development and testing, do not commit production private keys or long-lived self-signed certificates. Generate ephemeral, pure-Python dev certificates on demand:
```bash
python scripts/generate_dev_certs.py
# Or via Makefile:
make certs
make certs-verify
```
The generator creates an RSA private key (`dev-key.pem`) and an X.509 v3 certificate (`dev-cert.pem`) with Subject Alternative Names (`localhost`, `pii-sanitizer`, `127.0.0.1`) saved under `pii-sanitizer/certs/`.

### 2. Production Mutual TLS (mTLS) & Institutional PKI
In production financial deployments under CMN 4.893/2021:
- Replace self-signed dev certificates with certificates issued by your organization's internal Public Key Infrastructure (PKI) or automated Kubernetes `cert-manager`.
- Enable mutual TLS (mTLS) by supplying the institutional CA bundle to Kong Gateway (`lua_ssl_trusted_certificate`) and enabling `ssl_verify: true` in the `bcb-pii-sanitizer` plugin configuration.
- Enforce TLS 1.3 or minimum TLS 1.2 with strict cipher suites (`ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-ECDSA-AES256-GCM-SHA384`).

### 3. Secret Management & Key Rotation
- **Never commit `.env` or API credentials to version control**. `.env` is ignored by `.gitignore`.
- **Secret Vaults**: Inject `KONG_LICENSE_DATA`, `OPENAI_API_KEY`, and AWS credentials at runtime using an enterprise secret store (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Kubernetes External Secrets Operator).
- **Rotation Cadence**:
  - API Keys & Tokens: Rotate at least every 90 days or immediately upon personnel offboarding.
  - TLS Certificates: Automate renewals 30 days prior to expiration via ACME / `cert-manager`.
  - Master Encryption Keys: Enforce annual KMS key rotation with cryptographic envelope encryption.

> [!WARNING]
> Software alone cannot guarantee regulatory certification. Institutional compliance requires internal governance, vendor risk management, operational continuity planning, and qualified legal counsel.
