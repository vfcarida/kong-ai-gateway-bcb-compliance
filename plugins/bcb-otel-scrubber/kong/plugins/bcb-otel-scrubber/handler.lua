-- ==============================================================================
-- Plugin: bcb-otel-scrubber
-- Description: GenAI Privacy Scrubber Plugin (Kong Log Serialization Layer).
--              Operates during the `log` phase to redact raw prompt and completion
--              payloads (`gen_ai.prompt`, `gen_ai.completion`, `ai.prompt`,
--              `ai.completion`) within Kong's internal log serialization dictionary
--              (`kong.log.set_serialize_value`), preventing leakage into log sinks
--              (file-log, tcp-log, sys-log).
--
-- Note on OpenTelemetry Spans:
--              Kong's Lua runtime does not directly intercept native OTLP span
--              attributes. APM distributed tracing spans emitted via Kong's bundled
--              `opentelemetry` plugin are scrubbed downstream by the OpenTelemetry
--              Collector's `attributes/redact_genai` processor before egress to APM
--              backends (Jaeger, Datadog, Grafana Tempo).
--              This dual-layer approach provides defense-in-depth confidentiality
--              while strictly preserving operational and FinOps metrics
--              (`gen_ai.usage.*`, model, system, latencies).
-- Compliance: Resolução CMN 4893/21 & BCB 85/21
-- ==============================================================================

local BCBOTelScrubberHandler = {
  PRIORITY = 90, -- Runs after proxy phase during log/header processing
  VERSION = "2.0.0",
}

--- Intercepts log serialization to sanitize GenAI attributes for log exporters
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
