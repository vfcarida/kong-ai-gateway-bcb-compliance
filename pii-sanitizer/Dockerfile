# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="DevSecOps Team"
LABEL description="PII Sanitizer Service — Kong AI Gateway Reference Architecture"
LABEL version="2.0.0"

# Segurança: não rodar como root
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copiar dependências do builder
COPY --from=builder /install /usr/local

# Copiar código da aplicação e certificados de desenvolvimento
COPY app/ ./app/
COPY certs/ ./certs/

# Configuração (TLS Terminated - Resolução CMN 4.893/2021)
ENV PORT=8443
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SSL_KEYFILE=/app/certs/dev-key.pem
ENV SSL_CERTFILE=/app/certs/dev-cert.pem

EXPOSE 8443

USER appuser

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, ssl; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlopen('https://localhost:8443/health', context=ctx)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/app/certs/dev-key.pem", "--ssl-certfile", "/app/certs/dev-cert.pem", "--workers", "2"]
