local helpers = require "spec.helpers"
local cjson = require "cjson.safe"

describe("Plugin: bcb-pii-sanitizer", function()
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
end)
