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

> [!WARNING]
> Software alone cannot guarantee regulatory certification. Institutional compliance requires internal governance, vendor risk management, operational continuity planning, and qualified legal counsel.
