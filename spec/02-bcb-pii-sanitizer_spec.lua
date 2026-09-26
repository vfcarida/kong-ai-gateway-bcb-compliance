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
      assert.same({ "placeholder", "synthetic" }, redact_field.one_of)
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
