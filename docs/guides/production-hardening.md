# Production Hardening Guide

This document establishes the architecture, network controls, secret management, and cryptographic standards necessary to deploy the **Kong AI Gateway BCB Compliance** reference architecture in production banking and payment environments under **Resolução CMN nº 4.893/2021** (as amended by **CMN nº 5.274/2025**) and **Resolução BCB nº 85/2021**.

---

## 🏛️ Production Architecture Overview

In a regulated production environment, the AI Gateway acts as the Policy Enforcement Point (PEP) governing all Generative AI model interactions across internal microservices.

```mermaid
flowchart TD
    subgraph ClientVPC ["Internal Banking VPC / Trusted Zone"]
        BankingApp["Core Banking / Mobile App Backend"]
    end

    subgraph GatewayCluster ["Kubernetes DMZ / AI Gateway Ingress"]
        KongPEP["Kong AI Gateway (ReplicaSet)"]
        SanitizerPool["PII Sanitizer Microservice Pool (HPA)"]
    end

    subgraph SecurityServices ["Enterprise Security Infrastructure"]
        Vault[("HashiCorp Vault / AWS Secrets Manager")]
        PKI["Internal PKI / cert-manager CA"]
        WORM[("Off-Host Tamper-Evident WORM Storage<br/>(AWS S3 Object Lock / Azure Immutable)")]
        SIEM["Central SIEM / SOC (Splunk, Elastic)"]
    end

    subgraph UpstreamAI ["Approved Model Providers"]
        Bedrock["AWS Bedrock (sa-east-1)"]
        AzureAI["Azure OpenAI (Private Endpoint)"]
        PrivateLLM["On-Premises Dedicated Model Cluster"]
    end

    BankingApp -->|mTLS / Port 443| KongPEP
    KongPEP <-->|mTLS / Port 8443 (ssl_verify=true)| SanitizerPool
    KongPEP -->|Private Link / HTTPS| UpstreamAI
    KongPEP -.->|Fetch Secrets| Vault
    SanitizerPool -.->|Cert Rotation| PKI
    KongPEP -->|Secure Fluent Bit Shipper| WORM
    KongPEP -->|Audit Events| SIEM
```

---

## 🔒 1. Management Plane Isolation & RBAC

### Loopback Binding
Never expose Kong's Admin API (`8001`, `8444`) or Kong Manager GUI (`8002`) to public or cross-VPC networks. In production containers and Kubernetes pods:
- Bind `KONG_ADMIN_LISTEN` exclusively to `127.0.0.1:8001` or omit published ports in Kubernetes Service definitions.
- Direct administrative access through Kubernetes `kubectl port-forward` or bastion hosts over authenticated VPN.

### Enterprise Role-Based Access Control (RBAC)
When deploying Kong Gateway Enterprise:
```env
KONG_ENFORCE_RBAC=on
KONG_ADMIN_GUI_AUTH=basic-auth
KONG_RBAC_SESSION_CONF={"secret":"<vault-injected-session-secret>","cookie_secure":true}
```
- Define fine-grained RBAC roles: `AI-Policy-Admin` (can modify routes and guardrails), `Compliance-Auditor` (read-only access to configuration and audit logs).
- Enforce Single Sign-On (SSO) with OpenID Connect (OIDC / Okta / Azure Entra ID) and mandatory Multi-Factor Authentication (MFA).

---

## 🔐 2. In-Transit Encryption & Mutual TLS (mTLS)

### Kong to PII Sanitizer mTLS
In local sandbox mode, communication uses self-signed certificates with `ssl_verify: false`. In production:
1. **Provision Institutional Certificates**: Issue certificates signed by an internal root/intermediate Certificate Authority using `cert-manager`.
2. **Enable Gateway SSL Verification**:
   ```yaml
   plugins:
     - name: bcb-pii-sanitizer
       config:
         sanitizer_url: "https://pii-sanitizer.internal.bank:8443/sanitize"
         ssl_verify: true
         timeout_ms: 1500
         keepalive_timeout_ms: 60000
         keepalive_pool_size: 100
   ```
3. **Mount Institutional CA Bundle**: In Kong's container environment:
   ```env
   KONG_LUA_SSL_TRUSTED_CERTIFICATE=/etc/ssl/certs/internal-ca-bundle.crt
   KONG_LUA_SSL_VERIFY_DEPTH=3
   ```
4. **Enforce Modern TLS Protocols & Ciphers**:
   ```env
   KONG_SSL_PROTOCOLS=TLSv1.2 TLSv1.3
   KONG_SSL_CIPHERS=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305
   ```

---

## 📦 3. Production Lockdown: Disabling Development Mock Endpoints

The `pii-sanitizer` service includes mock LLM endpoints (`/mock-llm/*`) and last-request memory inspection probes for local end-to-end testing. **These must be locked down in production**:

```env
# Disable mock LLM routes and memory inspection probes
ENABLE_MOCK_LLM=false
```

When set to `false`, attempts to access `/mock-llm/v1/chat/completions`, `/mock-llm/last-request`, or `/mock-llm/reset` immediately return RFC 7807 `404 Not Found` Problem Details and no prompt payloads are stored in memory.

---

## 🏛️ 4. Tamper-Evident WORM Audit Log Storage (CMN 4.893/2021 Art. 40)

> [!CRITICAL]
> **Legal Admissibility Warning**:
> Gateway file logs written to standard disk mounts (`/tmp/audit-logs/kong-audit.log`) are mutable and subject to tampering or deletion. They do not fulfill the evidentiary standards of **Resolution CMN nº 4.893/2021 Article 40** or **Resolution BCB nº 85/2021**.

### Recommended Production Log Shipping Pipeline:
1. Configure Kong to serialize JSON audit entries using `bcb-otel-scrubber` (stripping raw prompts while preserving token counts and entity detection metadata).
2. Deploy a lightweight daemon (e.g., **Fluent Bit**, **Vector**, or **Filebeat**) as a Kubernetes DaemonSet or sidecar.
3. Stream logs over encrypted TLS directly to an **off-host WORM (Write Once, Read Many) object store**:
   - **AWS S3 Object Lock**: Enabled in **Compliance Mode** with a mandatory 5-year retention period (`legal-hold=ON`).
   - **Azure Immutable Blob Storage**: Legal hold with time-based retention policy.
   - **Google Cloud Storage Bucket Lock**: Retention policy with retention locking.
4. Concurrently forward security events to your Security Operations Center (SOC) / SIEM via syslog over TLS.

---

## 🔑 5. Secret Management & Key Rotation

- **Zero Plaintext Secrets**: Never store API tokens, database passwords, or private keys in repository commits, Docker images, or unencrypted ConfigMaps.
- **Dynamic Secret Injection**:
  - In Kubernetes, utilize **External Secrets Operator (ESO)** or HashiCorp Vault Agent Injector to deliver credentials directly into container memory via ephemeral tmpfs volumes.
- **Rotation Schedules**:
  - **Model API Keys** (`OPENAI_API_KEY`, etc.): Rotate every 90 days.
  - **TLS Certificates**: Automate rotation 30 days prior to expiration via ACME / `cert-manager`.
  - **AWS IAM Credentials**: Employ short-lived IAM Roles for Service Accounts (IRSA) or AWS STS AssumeRole rather than static IAM user keys.

---

## ⚡ 6. High Availability & Fail-Closed Resilience

1. **Gateway Replicas**: Deploy a minimum of 3 Kong Gateway replicas across multiple Availability Zones with pod anti-affinity.
2. **PII Sanitizer Horizontal Pod Autoscaling (HPA)**:
   - Scale based on CPU utilization (>70%) and HTTP request rate.
   - Maintain a minimum of 2 replicas to ensure zero-downtime rolling updates.
3. **Fail-Closed Semantics**:
   - Verify that `fail_open` is strictly set to `false` in `config/kong.yaml`.
   - If the PII Sanitizer microservice becomes unreachable or exceeds the 1500ms timeout, the gateway returns RFC 7807 `502 Bad Gateway`, preventing unredacted financial PII from reaching third-party models.
4. **Denial of Wallet Protection (OWASP LLM10:2025)**:
   - In Kong Enterprise deployments, activate `ai-rate-limiting-advanced` enforcing hourly and daily quotas on `gen_ai.usage.total_tokens` per consumer/department.

---

## ☸️ 7. Declarative Kubernetes Deployment (KIC & Kustomize)

The `k8s/` directory contains complete, production-grade Kubernetes manifests utilizing Kustomize:

```bash
# 1. Inspect manifests
kubectl kustomize k8s/

# 2. Deploy to Kubernetes cluster
kubectl apply -k k8s/

# 3. Verify rollout status
kubectl rollout status deployment/pii-sanitizer -n kong-ai-compliance
kubectl rollout status deployment/otel-collector -n kong-ai-compliance

# 4. Verify KongPlugin Custom Resources
kubectl get kongplugins -n kong-ai-compliance
```

### Deployed Resources:
- **`Namespace`**: `kong-ai-compliance` with BCB compliance metadata labels.
- **`KongPlugin` CRDs**: `bcb-pii-sanitizer` and `bcb-otel-scrubber` defining fail-closed, keepalive-pooled policies.
- **`pii-sanitizer`**: 2-replica `Deployment` with non-root security context (`runAsNonRoot: true`, capabilities dropped) and `ClusterIP` HTTPS service.
- **`otel-collector`**: OpenTelemetry Collector Contrib with span redaction pipeline.
- **`Ingress`**: Ingress resource binding custom plugins to `/llm-proxy` routes.
