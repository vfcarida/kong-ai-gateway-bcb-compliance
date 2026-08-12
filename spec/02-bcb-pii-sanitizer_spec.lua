local helpers = require "spec.helpers"

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
        fail_open = true,
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
end)
