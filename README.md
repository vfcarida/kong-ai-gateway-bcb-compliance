# 🛡️ Kong AI Gateway — PoC Blindagem PII

> **Compliance: Resolução BCB nº 538/2025 | Prevenção de Vazamento de Dados em Inferência LLM**

Prova de Conceito (PoC) que estabelece o **Kong AI Gateway** como plano de controle centralizado para chamadas de inferência a LLMs na AWS (Bedrock/SageMaker), com **ofuscação nativa e em tempo real de Informações Pessoalmente Identificáveis (PII)** — foco especial em **CPFs brasileiros**.

---

## 📋 Índice

- [Motivação](#-motivação)
- [Arquitetura](#-arquitetura)
- [Pré-requisitos](#-pré-requisitos)
- [Quickstart](#-quickstart)
- [Guia de Configuração](#-guia-de-configuração)
- [Teste de Integração](#-teste-de-integração)
- [Auditoria e Compliance BCB](#-auditoria-e-compliance-bcb)
- [Mapeamento BCB 538/2025](#-mapeamento-bcb-5382025)
- [Troubleshooting](#-troubleshooting)
- [Estrutura do Projeto](#-estrutura-do-projeto)

---

## 🎯 Motivação

### O Problema

Nossas aplicações interagem com LLMs na AWS diretamente via SDKs (`boto3`), criando:

- **Acoplamento forte** — cada aplicação gerencia sua própria conexão com o LLM
- **Vulnerabilidade de governança** — dados sensíveis (CPF, nomes, valores) podem vazar para provedores de IA
- **Falta de rastreabilidade** — sem trilha de auditoria centralizada das chamadas de inferência

### A Regulação

A **Resolução BCB nº 538/2025** (vigente desde 1º de março de 2026) exige controles prescritivos de:

| Controle BCB | Descrição |
|---|---|
| **Prevenção de Vazamento (DLP)** | Mecanismos para evitar exfiltração de dados sensíveis |
| **Rastreabilidade** | Monitoramento e registro robusto de eventos e transações |
| **Governança sobre Terceiros** | Padrões de segurança aplicados a fornecedores (incluindo nuvem/IA) |
| **Criptografia** | Proteção da confidencialidade e integridade dos dados |

### A Solução

O **Kong AI Gateway** atua como plano de controle centralizado, interceptando todas as chamadas de inferência e aplicando políticas de segurança automaticamente:

```
App → Kong Gateway → [PII Sanitizer] → [AI Proxy] → AWS Bedrock
                          ↓
                    Audit Log (BCB)
```

---

## 🏗️ Arquitetura

```
┌──────────────────┐     ┌─────────────────────────────────────────┐     ┌──────────────┐
│                  │     │          Docker Compose Network          │     │              │
│  🐍 Cliente      │     │                                         │     │  ☁️  AWS      │
│                  │ ──► │  🦍 Kong Gateway    🛡️ PII Sanitizer    │ ──► │  Bedrock     │
│  test_kong_      │     │     :8000/:8001        :8088            │     │  Titan/      │
│  proxy.py        │ ◄── │                                         │ ◄── │  Claude/     │
│                  │     │     📄 Audit Log (/tmp/kong-audit.log)  │     │  Llama       │
└──────────────────┘     └─────────────────────────────────────────┘     └──────────────┘
```

### Fluxo de Dados

1. **Cliente** envia prompt com dados sensíveis (CPF, nome, valores) → Kong `:8000/llm-proxy`
2. **Plugin `pre-function`** (Lua) intercepta o body e envia ao **PII Sanitizer** `:8088/sanitize`
3. **PII Sanitizer** (FastAPI) detecta entidades via regex e heurísticas, retorna texto ofuscado
4. **Plugin `ai-proxy`** encaminha prompt sanitizado ao **Amazon Bedrock**
5. Resposta do LLM retorna ao cliente via Kong
6. **Plugin `file-log`** registra metadados de auditoria para compliance BCB

### Componentes

| Componente | Tecnologia | Licença | Função |
|---|---|---|---|
| Kong Gateway | Kong Enterprise 3.14 LTS (DB-less) | Trial 30 dias | Orquestração, roteamento LLM |
| PII Sanitizer | Python 3.12 + FastAPI | Open Source | Detecção e ofuscação de PII |
| Audit Logger | Kong file-log plugin | Incluso | Trilha de auditoria |

---

## 📦 Pré-requisitos

| Requisito | Versão | Obrigatório |
|---|---|---|
| Docker + Docker Compose | 24.0+ | ✅ |
| Python | 3.10+ | ✅ (para testes) |
| Licença Kong Enterprise | Trial 30 dias | ⚠️ (para `ai-proxy`) |
| Credenciais AWS | IAM com acesso Bedrock | ⚠️ (para E2E) |

> **💡 Sem licença Enterprise?** A PoC funciona parcialmente — o PII Sanitizer opera de forma independente e pode ser testado com `--sanitizer-only`.

### Como obter o Trial de 30 dias (Kong Enterprise)

1. Acesse **[konnect.konghq.com](https://konnect.konghq.com/)** e crie uma conta gratuita
2. No dashboard, vá em **Gateway Manager** → **Gerar Licença**
3. Copie o JSON da licença
4. Cole no arquivo `.env` na variável `KONG_LICENSE_DATA`

---

## 🚀 Quickstart

### 1. Clonar e configurar

```bash
git clone <repo-url>
cd kong-ai-gateway-bcb-compliance

# Copiar template de variáveis de ambiente
cp .env.example .env
```

Edite o arquivo `.env` com suas credenciais:

```bash
# Mínimo necessário:
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJal...
AWS_REGION=us-east-1

# Opcional (para ai-proxy nativo):
KONG_LICENSE_DATA='{"license":{"payload":...}}'
```

### 2. Subir a infraestrutura

```bash
docker compose up -d --build
```

Aguarde os health checks passarem (30-60 segundos):

```bash
# Verificar status dos containers
docker compose ps

# Health check do PII Sanitizer
curl -s http://localhost:8088/health | python -m json.tool

# Health check do Kong
curl -s http://localhost:8001/status | python -m json.tool
```

### 3. Executar testes

```bash
# Instalar dependência de teste
pip install requests

# Teste apenas o PII Sanitizer (sem necessidade de AWS)
python test_kong_proxy.py --sanitizer-only

# Teste completo E2E (requer AWS + licença Kong)
python test_kong_proxy.py
```

---

## ⚙️ Guia de Configuração

### Trocar de Modelo LLM

A implementação é **model-agnostic**. Para trocar de modelo, edite apenas o `.env`:

```bash
# Amazon Titan (padrão)
AI_MODEL_NAME=amazon.titan-text-express-v1

# Anthropic Claude 3 Sonnet
AI_MODEL_NAME=anthropic.claude-3-sonnet-20240229-v1:0

# Anthropic Claude 3 Haiku (mais rápido)
AI_MODEL_NAME=anthropic.claude-3-haiku-20240307-v1:0

# Meta Llama 3 70B
AI_MODEL_NAME=meta.llama3-70b-instruct-v1:0
```

Após alterar, reinicie o Kong:

```bash
docker compose restart kong-gateway
```

### Trocar Modo de Redação PII

```bash
# Placeholders ([REDACTED_CPF_1], [REDACTED_EMAIL_1], etc.)
PII_REDACT_TYPE=placeholder

# Dados sintéticos (CPF falso válido, email falso, etc.)
PII_REDACT_TYPE=synthetic
```

### Adicionar Novos Padrões PII

Edite `pii-sanitizer/app/main.py` e adicione ao array `PII_PATTERNS`:

```python
PII_PATTERNS.append((
    "CNPJ",                                              # Tipo
    re.compile(r"\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}"),    # Regex
    0,                                                    # Prioridade
))
```

Rebuild o container:

```bash
docker compose up -d --build pii-sanitizer
```

---

## 🧪 Teste de Integração

### Teste Isolado do PII Sanitizer

```bash
python test_kong_proxy.py --sanitizer-only
```

Este teste **não requer** licença Enterprise nem credenciais AWS. Ele valida:

- ✅ Detecção de CPF formatado (`123.456.789-00`)
- ✅ Detecção de CPF numérico (`12345678900`)
- ✅ Detecção de emails (`maria@empresa.com`)
- ✅ Detecção de telefones (`(11) 99876-5432`)
- ✅ Detecção de nomes próprios (`João da Silva`)
- ✅ Detecção de valores monetários (`R$ 50.000`)
- ✅ Controle negativo (sem falsos positivos)

### Teste com Dados Sintéticos

```bash
python test_kong_proxy.py --sanitizer-only --synthetic
```

Gera dados falsos mas coerentes em vez de placeholders:
- CPF → CPF falso matematicamente válido
- Email → email em domínio fictício
- Telefone → número brasileiro falso
- Nome → nome aleatório

### Teste E2E via Kong

```bash
python test_kong_proxy.py
```

Requer:
- ✅ Docker Compose rodando (`docker compose up -d`)
- ✅ Credenciais AWS válidas no `.env`
- ✅ Licença Kong Enterprise (trial 30 dias) para o `ai-proxy`

### Teste Manual via cURL

```bash
curl -s -X POST http://localhost:8000/llm-proxy \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "Meu nome é João da Silva, CPF 123.456.789-00. Qual meu saldo?"
      }
    ]
  }' | python -m json.tool
```

---

## 📊 Auditoria e Compliance BCB

### Consultar Logs de Auditoria

```bash
# Ver todos os logs de auditoria do Kong
docker compose exec kong-gateway cat /tmp/kong-audit.log | python -m json.tool

# Ver logs do PII Sanitizer (detalhes das detecções)
docker compose logs pii-sanitizer --tail=100
```

### Campos de Auditoria para Relatório BCB

Os logs do Kong incluem metadados estruturados do PII Sanitizer:

```json
{
  "request": {
    "uri": "/llm-proxy",
    "method": "POST",
    "headers": {
      "x-request-id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  },
  "response": {
    "status": 200
  },
  "latencies": {
    "proxy": 1234,
    "kong": 56,
    "request": 1290
  },
  "started_at": 1719158400000
}
```

Os logs do **PII Sanitizer** (via `docker compose logs`) incluem:

```
2026-06-23 14:30:00 [INFO] pii-sanitizer: PII detectado: 3 entidades [NAME, CPF, MONEY] | tempo: 0.45ms
```

### Gerando Relatório de Compliance

```bash
# Contar total de interceptações PII por tipo
docker compose logs pii-sanitizer --no-log-prefix | \
  grep "PII detectado" | \
  wc -l

# Exportar logs para arquivo (para auditores)
docker compose logs pii-sanitizer --no-log-prefix > relatorio-pii-$(date +%Y%m%d).log
```

---

## 📋 Mapeamento BCB 538/2025

| # | Controle Exigido (BCB 538/2025) | Implementação na PoC | Status |
|---|---|---|---|
| 1 | **Prevenção de Vazamento de Informações (DLP)** | PII Sanitizer intercepta e ofusca CPF, nomes, emails, telefones e valores antes de enviar ao LLM | ✅ |
| 2 | **Rastreabilidade** | `file-log` + `correlation-id` (X-Request-ID UUID) registram cada request com trilha de auditoria | ✅ |
| 3 | **Governança sobre Terceiros** | Kong como control plane centralizado — provedores LLM nunca recebem dados originais | ✅ |
| 4 | **Criptografia em Trânsito** | Kong suporta TLS na porta `8443`; comunicação com Bedrock via HTTPS | ✅ |
| 5 | **Controle de Acesso** | Kong Admin API isolada (porta `8001`); AI proxy gerencia autenticação AWS | ✅ |
| 6 | **Gestão de Vulnerabilidades** | Container PII Sanitizer com non-root user, multi-stage build, health checks | ✅ |
| 7 | **Segregação de Ambientes** | Rede Docker isolada (`kong-ai-net`); PII Sanitizer sem acesso externo | ✅ |

---

## 🔧 Troubleshooting

### Container do Kong não sobe

```bash
# Verificar logs de erro
docker compose logs kong-gateway --tail=50

# Problema comum: YAML inválido
docker compose exec kong-gateway kong config parse /usr/local/kong/declarative/kong.yaml
```

### PII Sanitizer retorna erro

```bash
# Verificar se o container está saudável
docker compose ps pii-sanitizer

# Testar endpoint diretamente
curl -X POST http://localhost:8088/sanitize \
  -H "Content-Type: application/json" \
  -d '{"text": "CPF 123.456.789-00", "redact_type": "placeholder"}'

# Ver documentação interativa
# Abra http://localhost:8088/docs no navegador
```

### ai-proxy retorna 503

O plugin `ai-proxy` requer licença Enterprise:

1. Verifique se `KONG_LICENSE_DATA` está preenchido no `.env`
2. Obtenha um trial em [konnect.konghq.com](https://konnect.konghq.com/)
3. Enquanto isso, teste com `python test_kong_proxy.py --sanitizer-only`

### Erro de credenciais AWS

```bash
# Verificar se as credenciais estão chegando ao container
docker compose exec kong-gateway env | grep AWS

# Testar acesso ao Bedrock localmente
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --region us-east-1 \
  --body '{"inputText":"Hello"}' \
  output.json
```

---

## 📁 Estrutura do Projeto

```
kong-ai-gateway-bcb-compliance/
├── config/
│   └── kong.yaml                # Configuração declarativa do Kong (DB-less)
├── pii-sanitizer/
│   ├── Dockerfile               # Build multi-stage do serviço PII
│   ├── requirements.txt         # Dependências Python (FastAPI, uvicorn)
│   └── app/
│       ├── __init__.py
│       └── main.py              # Engine de detecção PII (regex + heurísticas)
├── logs/                        # Volume para audit logs (git-ignored)
├── docker-compose.yml           # Orquestração dos containers
├── .env.example                 # Template de variáveis de ambiente
├── .gitignore                   # Arquivos ignorados pelo Git
├── test_kong_proxy.py           # Script de teste de integração
└── README.md                    # Este arquivo
```

---

## 📄 Licença

Este projeto é uma Prova de Conceito interna para compliance regulatório.

**Kong Gateway Enterprise** requer licença comercial (trial de 30 dias disponível).
O **PII Sanitizer** customizado é código proprietário da organização.
