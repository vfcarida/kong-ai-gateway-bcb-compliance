# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="DevSecOps Team"
LABEL description="PII Sanitizer Service — Kong AI Gateway PoC (BCB 538/2025)"
LABEL version="1.0.0"

# Segurança: não rodar como root
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copiar dependências do builder
COPY --from=builder /install /usr/local

# Copiar código da aplicação
COPY app/ ./app/

# Configuração
ENV PORT=8088
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8088

USER appuser

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8088/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088", "--workers", "2"]
