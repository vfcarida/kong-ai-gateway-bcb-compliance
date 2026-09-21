local helpers = require "spec.helpers"

describe("Plugin: bcb-otel-scrubber", function()
  describe("Unit: handler:log() serialization", function()
    local handler = require "kong.plugins.bcb-otel-scrubber.handler"

    it("redacts prompt and completion and sets compliance flags in log serializer", function()
      local values = {}
      _G.kong = {
        log = {
          set_serialize_value = function(k, v)
            values[k] = v
          end
        }
      }

      handler:log({
        scrub_prompt = true,
        scrub_completion = true,
        replacement_text = "[REDACTED_BY_BCB_COMPLIANCE_POLICY]",
      })

      assert.equal("[REDACTED_BY_BCB_COMPLIANCE_POLICY]", values["gen_ai.prompt"])
      assert.equal("[REDACTED_BY_BCB_COMPLIANCE_POLICY]", values["ai.prompt"])
      assert.equal("[REDACTED_BY_BCB_COMPLIANCE_POLICY]", values["gen_ai.completion"])
      assert.equal("[REDACTED_BY_BCB_COMPLIANCE_POLICY]", values["ai.completion"])
      assert.is_true(values["bcb.compliance.otel_scrubbed"])
      assert.equal("CMN_4893_21_BCB_85_21", values["bcb.compliance.policy"])
    end)

    it("respects scrub_prompt = false and scrub_completion = false flags", function()
      local values = {}
      _G.kong = {
        log = {
          set_serialize_value = function(k, v)
            values[k] = v
          end
        }
      }

      handler:log({
        scrub_prompt = false,
        scrub_completion = false,
        replacement_text = "[REDACTED_BY_BCB_COMPLIANCE_POLICY]",
      })

      assert.is_nil(values["gen_ai.prompt"])
      assert.is_nil(values["gen_ai.completion"])
      assert.is_true(values["bcb.compliance.otel_scrubbed"])
      assert.equal("CMN_4893_21_BCB_85_21", values["bcb.compliance.policy"])
    end)
  end)

  describe("Integration: Gateway route", function()
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

    it("serves requests through route configured with bcb-otel-scrubber", function()
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
end)
