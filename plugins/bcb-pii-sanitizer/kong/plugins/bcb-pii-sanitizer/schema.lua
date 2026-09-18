local typedefs = require "kong.db.schema.typedefs"

return {
  name = "bcb-pii-sanitizer",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            sanitizer_url = {
              type = "string",
              required = true,
              default = "http://pii-sanitizer:8088/sanitize",
            },
          },
          {
            timeout_ms = {
              type = "number",
              required = true,
              default = 5000,
            },
          },
          {
            redact_type = {
              type = "string",
              required = true,
              default = "placeholder",
              one_of = { "placeholder", "synthetic" },
            },
          },
          {
            cache_ttl_seconds = {
              type = "number",
              required = true,
              default = 300,
            },
          },
          {
            fail_open = {
              type = "boolean",
              required = true,
              default = false,
            },
          },
        },
      },
    },
  },
}
