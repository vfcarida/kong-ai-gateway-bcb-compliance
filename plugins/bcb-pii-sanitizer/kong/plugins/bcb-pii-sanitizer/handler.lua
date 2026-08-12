-- ==============================================================================
-- Plugin: bcb-pii-sanitizer
-- Description: Intercepts LLM prompt payloads, identifies Brazilian PII entities,
--              rewrites request bodies with redacted/synthetic placeholders, and
--              injects audit metrics into Kong log serialization.
-- Compliance: Resolução CMN 4893/21 & BCB 85/21
-- ==============================================================================

local cjson = require "cjson.safe"
local http = require "resty.http"

local BCBPIISanitizerHandler = {
  PRIORITY = 1010, -- Execute before ai-proxy (1000)
  VERSION = "2.0.0",
}

--- Inspects and sanitizes messages inside OpenAI-compatible chat payload
-- @param config Plugin configuration record
function BCBPIISanitizerHandler:access(config)
  kong.service.request.enable_buffering()

  local body_raw = kong.request.get_raw_body()
  if not body_raw or body_raw == "" then
    return
  end

  local ok, body_json = pcall(cjson.decode, body_raw)
  if not ok or not body_json or type(body_json) ~= "table" then
    kong.log.warn("[bcb-pii-sanitizer] Request body is not valid JSON, skipping processing.")
    return
  end

  local messages = body_json.messages
  if not messages or type(messages) ~= "table" or #messages == 0 then
    kong.log.debug("[bcb-pii-sanitizer] No 'messages' array present in payload.")
    return
  end

  local cache = ngx.shared.kong_cache
  local redact_type = config.redact_type or "placeholder"
  local total_pii_count = 0
  local pii_types = {}
  local modified = false

  for idx, msg in ipairs(messages) do
    if msg.role == "user" and msg.content and type(msg.content) == "string" and #msg.content > 0 then
      local text = msg.content
      local cache_key = "bcb_pii:" .. ngx.md5(text .. ":" .. redact_type)
      local cached_res = nil

      if cache then
        cached_res = cache:get(cache_key)
      end

      local sanitize_result = nil

      if cached_res then
        local parse_ok, decoded = pcall(cjson.decode, cached_res)
        if parse_ok and decoded then
          sanitize_result = decoded
          kong.log.debug("[bcb-pii-sanitizer] Cache hit for message prompt.")
        end
      end

      if not sanitize_result then
        local httpc = http.new()
        httpc:set_timeout(config.timeout_ms or 5000)

        local req_payload = cjson.encode({
          text = text,
          redact_type = redact_type,
        })

        local res, req_err = httpc:request_uri(config.sanitizer_url, {
          method = "POST",
          body = req_payload,
          headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
          },
        })

        if req_err or not res or res.status ~= 200 then
          kong.log.err("[bcb-pii-sanitizer] Failed to connect to sanitizer microservice: ", req_err or (res and res.status))
          if not config.fail_open then
            return kong.response.exit(502, {
              type = "https://tools.ietf.org/html/rfc7807",
              title = "Bad Gateway",
              status = 502,
              detail = "PII Sanitization service unavailable and fail-closed policy is active.",
              instance = kong.request.get_path(),
            }, { ["Content-Type"] = "application/problem+json" })
          end
        else
          local parse_ok, decoded = pcall(cjson.decode, res.body)
          if parse_ok and decoded then
            sanitize_result = decoded
            if cache and config.cache_ttl_seconds > 0 then
              cache:set(cache_key, cjson.encode(sanitize_result), config.cache_ttl_seconds)
            end
          end
        end
      end

      if sanitize_result and sanitize_result.sanitized_text then
        if sanitize_result.sanitized_text ~= msg.content then
          body_json.messages[idx].content = sanitize_result.sanitized_text
          modified = true
        end

        local entities_count = sanitize_result.total_entities or 0
        total_pii_count = total_pii_count + entities_count

        if sanitize_result.pii_detected then
          for _, entity in ipairs(sanitize_result.pii_detected) do
            local entity_type = entity.type or "UNKNOWN"
            pii_types[entity_type] = (pii_types[entity_type] or 0) + 1
          end
        end
      end
    end
  end

  if modified then
    local new_body = cjson.encode(body_json)
    kong.service.request.set_raw_body(new_body)
  end

  -- Record compliance audit metrics into Kong shared context and log serialization
  if total_pii_count > 0 then
    kong.ctx.shared.pii_sanitizer = {
      pii_identified = total_pii_count,
      pii_types = pii_types,
      redact_type = redact_type,
      timestamp = ngx.now(),
    }

    kong.log.set_serialize_value("ai.sanitizer.pii_identified", total_pii_count)
    kong.log.set_serialize_value("ai.sanitizer.pii_sanitized", total_pii_count)

    local pii_type_list = {}
    for k, _ in pairs(pii_types) do
      table.insert(pii_type_list, k)
    end
    kong.log.set_serialize_value("ai.sanitizer.pii_types", pii_type_list)
  end
end

return BCBPIISanitizerHandler
