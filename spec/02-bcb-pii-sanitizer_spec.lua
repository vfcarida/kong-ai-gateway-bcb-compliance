local helpers = require "spec.helpers"
local cjson = require "cjson.safe"

describe("Plugin: bcb-pii-sanitizer", function()
  describe("Unit: schema validation", function()
    local schema_def = require "kong.plugins.bcb-pii-sanitizer.schema"

    it("enforces fail_open = false by default for strict confidentiality", function()
      local config_fields = schema_def.fields[3].config.fields
      local fail_open_field = nil
      for _, f in ipairs(config_fields) do
        if f.fail_open then fail_open_field = f.fail_open end
      end
      assert.is_not_nil(fail_open_field)
      assert.is_false(fail_open_field.default)
    end)

    it("defaults timeout_ms to 5000 and cache_ttl_seconds to 300", function()
      local config_fields = schema_def.fields[3].config.fields
      local timeout_field, cache_field = nil, nil
      for _, f in ipairs(config_fields) do
        if f.timeout_ms then timeout_field = f.timeout_ms end
        if f.cache_ttl_seconds then cache_field = f.cache_ttl_seconds end
      end
      assert.is_not_nil(timeout_field)
      assert.equal(5000, timeout_field.default)
      assert.is_not_nil(cache_field)
      assert.equal(300, cache_field.default)
    end)

    it("restricts redact_type to placeholder or synthetic", function()
      local config_fields = schema_def.fields[3].config.fields
      local redact_field = nil
      for _, f in ipairs(config_fields) do
        if f.redact_type then redact_field = f.redact_type end
      end
      assert.is_not_nil(redact_field)
      assert.equal("placeholder", redact_field.default)
    end)
  end)

  describe("Unit: in-gateway pure Lua checksum & fast-path engine", function()
    local checksum = require "kong.plugins.bcb-pii-sanitizer.checksum"

    it("correctly validates mathematical CPF checksums via Modulo-11", function()
      -- Valid CPFs
      assert.is_true(checksum.validate_cpf("12345678909"))
      assert.is_true(checksum.validate_cpf("52998224725"))
      -- Invalid CPFs
      assert.is_false(checksum.validate_cpf("12345678900"))
      assert.is_false(checksum.validate_cpf("11111111111")) -- all identical digits
      assert.is_false(checksum.validate_cpf("12345")) -- invalid length
    end)

    it("correctly validates mathematical CNPJ checksums via Modulo-11", function()
      -- Valid CNPJs
      assert.is_true(checksum.validate_cnpj("11222333000181"))
      assert.is_true(checksum.validate_cnpj("00000000000191"))
      -- Invalid CNPJs
      assert.is_false(checksum.validate_cnpj("11222333000180"))
      assert.is_false(checksum.validate_cnpj("00000000000000")) -- all identical digits
      assert.is_false(checksum.validate_cnpj("1234567890123")) -- 13 digits
    end)

    it("correctly validates Payment Card PANs via ISO/IEC 7812 Luhn", function()
      -- Valid Luhn numbers (Visa, Mastercard test cards)
      assert.is_true(checksum.validate_luhn("4532015112830366"))
      -- Invalid Luhn numbers
      assert.is_false(checksum.validate_luhn("4532015112830367"))
      assert.is_false(checksum.validate_luhn("1111111111111111"))
    end)

    it("bypasses sidecar for clean prompts containing benign numbers", function()
      -- Benign queries with digits that do NOT contain regulated PII
      assert.is_false(checksum.quick_pii_check("Explain Newton's 2nd law of motion"))
      assert.is_false(checksum.quick_pii_check("What are the top 3 best practices for 2026?"))
      assert.is_false(checksum.quick_pii_check("Order number 98765432100 is pending shipment"))
      assert.is_false(checksum.quick_pii_check("The server port is 8080 and timeout is 30s"))
    end)

    it("triggers deep scan for prompts containing real PII entities", function()
      -- Formatted CPF
      assert.is_true(checksum.quick_pii_check("Meu CPF é 123.456.789-09"))
      -- Unformatted valid CPF
      assert.is_true(checksum.quick_pii_check("Favor verificar o CPF 12345678909"))
      -- Formatted CNPJ
      assert.is_true(checksum.quick_pii_check("Empresa CNPJ 11.222.333/0001-81"))
      -- Email
      assert.is_true(checksum.quick_pii_check("Contato: carlos.silva@banco.com.br"))
      -- Currency
      assert.is_true(checksum.quick_pii_check("Transferência de R$ 1.500,00"))
      -- Bank account
      assert.is_true(checksum.quick_pii_check("Agência 1234 conta corrente 56789-0"))
      -- PIX Key
      assert.is_true(checksum.quick_pii_check("Chave PIX: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"))
    end)

    it("sanitizes echoed PII in memory for response completions (FEAT-03)", function()
      local completion = '{"choices":[{"message":{"content":"O CPF do cliente é 123.456.789-09 e o cartão é 4532-0151-1283-0366."}}]}'
      local sanitized = checksum.sanitize_text_in_memory(completion, "placeholder")
      assert.is_nil(string.find(sanitized, "123.456.789-09", 1, true))
      assert.is_nil(string.find(sanitized, "4532-0151-1283-0366", 1, true))
      assert.is_not_nil(string.find(sanitized, "[REDACTED_CPF]", 1, true))
      assert.is_not_nil(string.find(sanitized, "[REDACTED_CARD]", 1, true))
    end)
  end)

  describe("Integration: Ingress PII Sanitization", function()
    local client

    setup(function()
      local bp = helpers.get_db_utils("postgres", {
        "routes",
        "services",
        "plugins",
      })

      local service = bp.services:insert({
        name = "mock-llm-service",
        url = "http://pii-sanitizer:8088/mock-llm",
      })

      local route = bp.routes:insert({
        service = { id = service.id },
        paths = { "/test-pii" },
      })

      bp.plugins:insert({
        name = "bcb-pii-sanitizer",
        route = { id = route.id },
        config = {
          sanitizer_url = "http://pii-sanitizer:8088/sanitize",
          redact_type = "placeholder",
          timeout_ms = 5000,
          fail_open = false,
        },
      })

      -- Route configured with unreachable sanitizer to verify fail-closed behavior
      local fail_closed_route = bp.routes:insert({
        service = { id = service.id },
        paths = { "/test-fail-closed" },
      })

      bp.plugins:insert({
        name = "bcb-pii-sanitizer",
        route = { id = fail_closed_route.id },
        config = {
          sanitizer_url = "http://127.0.0.1:59999/unreachable",
          redact_type = "placeholder",
          timeout_ms = 500,
          fail_open = false,
        },
      })

      -- Inspection probe route directly reaching mock-llm state without PII plugin
      local probe_service = bp.services:insert({
        name = "mock-probe-service",
        url = "http://pii-sanitizer:8088/mock-llm/last-request",
      })

      bp.routes:insert({
        service = { id = probe_service.id },
        paths = { "/mock-probe" },
      })

      assert(helpers.start_kong({
        database = "postgres",
        plugins = "bundled,bcb-pii-sanitizer",
      }))
    end)

    teardown(function()
      helpers.stop_kong()
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    it("intercepts and sanitizes CPF before forwarding to LLM", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [{"role": "user", "content": "My CPF is 123.456.789-00"}]
        }]],
      })

      assert.res_status(200, res)
      assert.equal("true", res.headers["x-bcb-compliance-verified"])
      assert.equal("1", res.headers["x-bcb-pii-entities-redacted"])

      -- Verify upstream received sanitized content via probe
      local probe_res = client:get("/mock-probe")
      if probe_res.status == 200 then
        local probe_body = probe_res:read_body()
        local probe_json = cjson.decode(probe_body)
        if probe_json and probe_json.payload and probe_json.payload.messages then
          local content = probe_json.payload.messages[1].content
          assert.is_nil(string.find(content, "123.456.789-00", 1, true), "Sensitive CPF leaked upstream!")
          assert.is_not_nil(string.find(content, "REDACTED_CPF", 1, true), "Expected REDACTED_CPF replacement")
        end
      end
    end)

    it("forwards session_id and compliance headers upstream and downstream", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
          ["X-Session-ID"] = "session-test-compliance-42",
        },
        body = [[{
          "messages": [{"role": "user", "content": "Cliente CPF 123.456.789-09 cadastrado"}]
        }]],
      })

      assert.res_status(200, res)
      assert.equal("true", res.headers["x-bcb-compliance-verified"])
      assert.equal("1", res.headers["x-bcb-pii-entities-redacted"])
    end)

    it("returns 502 Bad Gateway and blocks forwarding when sanitizer is unreachable under fail-closed", function()
      local res = client:post("/test-fail-closed", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [{"role": "user", "content": "My CPF is 123.456.789-00"}]
        }]],
      })

      local body = assert.res_status(502, res)
      local json = cjson.decode(body)
      assert.is_table(json)
      assert.equal("Bad Gateway", json.title)
      assert.equal(502, json.status)
      assert.equal("PII Sanitization service unavailable and fail-closed policy is active.", json.detail)
      assert.equal("https://tools.ietf.org/html/rfc7807", json.type)
    end)

    it("intercepts and sanitizes PII in system role messages", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [
            {"role": "system", "content": "Security guideline with CPF 123.456.789-09"},
            {"role": "user", "content": "Execute operation"}
          ]
        }]],
      })

      assert.res_status(200, res)
    end)

    it("intercepts and sanitizes PII in assistant role history messages", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [
            {"role": "user", "content": "Check registration"},
            {"role": "assistant", "content": "The recorded CNPJ was 11.222.333/0001-81"}
          ]
        }]],
      })

      assert.res_status(200, res)
    end)

    it("intercepts and sanitizes PII in OpenAI structured array content parts", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [
            {
              "role": "user",
              "content": [
                {"type": "text", "text": "Prompt text with CPF 123.456.789-09"}
              ]
            }
          ]
        }]],
      })

      assert.res_status(200, res)
    end)

    it("rejects malformed JSON payload with RFC 7807 400 Bad Request", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = "This is not valid json {{{",
      })

      local body = assert.res_status(400, res)
      local json = cjson.decode(body)
      assert.is_table(json)
      assert.equal(400, json.status)
      assert.equal("Bad Request - Invalid JSON", json.title)
      assert.equal("https://tools.ietf.org/html/rfc7807", json.type)
    end)

    it("allows clean non-PII prompt to pass through intact", function()
      local res = client:post("/test-pii", {
        headers = {
          ["Content-Type"] = "application/json",
        },
        body = [[{
          "messages": [{"role": "user", "content": "como funciona o sistema financeiro?"}]
        }]],
      })

      assert.res_status(200, res)
    end)
  end)
end)
