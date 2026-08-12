local typedefs = require "kong.db.schema.typedefs"

return {
  name = "bcb-otel-scrubber",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            scrub_prompt = {
              type = "boolean",
              required = true,
              default = true,
            },
          },
          {
            scrub_completion = {
              type = "boolean",
              required = true,
              default = true,
            },
          },
          {
            replacement_text = {
              type = "string",
              required = true,
              default = "[REDACTED_BY_BCB_COMPLIANCE_POLICY]",
            },
          },
        },
      },
    },
  },
}
