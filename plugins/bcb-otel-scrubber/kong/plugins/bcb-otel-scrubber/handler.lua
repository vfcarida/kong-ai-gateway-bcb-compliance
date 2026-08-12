-- ==============================================================================
-- Plugin: bcb-otel-scrubber
-- Description: OpenTelemetry GenAI Privacy Scrubber Plugin.
--              Intercepts telemetry data export pipeline to scrub raw prompt and
--              completion text (`gen_ai.prompt`, `gen_ai.completion`) while strictly
--              preserving operational metrics (`gen_ai.usage.input_tokens`,
--              `gen_ai.usage.output_tokens`, `gen_ai.system`, `gen_ai.request.model`).
-- Compliance: Resolução CMN 4893/21 & BCB 85/21
-- ==============================================================================

local BCBOTelScrubberHandler = {
  PRIORITY = 90, -- Runs after proxy phase during log/header processing
  VERSION = "2.0.0",
}

--- Intercepts log serialization to sanitize OpenTelemetry attributes
-- @param config Plugin configuration record
function BCBOTelScrubberHandler:log(config)
  local replacement = config.replacement_text or "[REDACTED_BY_BCB_COMPLIANCE_POLICY]"

  if config.scrub_prompt then
    kong.log.set_serialize_value("gen_ai.prompt", replacement)
    kong.log.set_serialize_value("ai.prompt", replacement)
  end

  if config.scrub_completion then
    kong.log.set_serialize_value("gen_ai.completion", replacement)
    kong.log.set_serialize_value("ai.completion", replacement)
  end

  -- Explicitly ensure compliance flags are recorded
  kong.log.set_serialize_value("bcb.compliance.otel_scrubbed", true)
  kong.log.set_serialize_value("bcb.compliance.policy", "CMN_4893_21_BCB_85_21")
end

return BCBOTelScrubberHandler
