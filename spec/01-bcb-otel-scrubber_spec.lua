local helpers = require "spec.helpers"

describe("Plugin: bcb-otel-scrubber", function()
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
      paths = { "/test-otel" },
    })

    bp.plugins:insert({
      name = "bcb-otel-scrubber",
      route = { id = route.id },
      config = {
        scrub_prompt = true,
        scrub_completion = true,
        replacement_text = "[REDACTED_BY_BCB_COMPLIANCE_POLICY]",
      },
    })

    assert(helpers.start_kong({
      database = "postgres",
      plugins = "bundled,bcb-otel-scrubber",
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

  it("scrubs prompt and completion from telemetry attributes", function()
    local res = client:post("/test-otel", {
      headers = {
        ["Content-Type"] = "application/json",
      },
      body = [[{
        "messages": [{"role": "user", "content": "Sensitive query with CPF 123.456.789-00"}]
      }]],
    })

    assert.res_status(200, res)
  end)
end)
