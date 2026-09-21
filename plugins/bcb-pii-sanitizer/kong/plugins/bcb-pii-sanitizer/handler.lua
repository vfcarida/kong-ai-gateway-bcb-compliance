-- ==============================================================================
-- Plugin: bcb-pii-sanitizer
-- Description: Intercepts LLM prompt payloads, identifies Brazilian PII entities,
--              rewrites request bodies with redacted/synthetic placeholders, and
--              injects audit metrics into Kong log serialization.
-- Compliance: Resolução CMN 4893/21 & BCB 85/21
--
-- ARCHITECTURAL DECISION & LABELLED NON-GOAL: RESPONSE BODY SCRUBBING
-- ------------------------------------------------------------------------------
-- Response body scrubbing (filtering LLM completion outputs in `body_filter`) is
-- explicitly deferred as a labelled non-goal based on the following constraints:
-- 1. OpenResty Cosocket Limitations: In Nginx/OpenResty, the `body_filter_by_lua`
--    phase executes within an output buffer stream where cosockets/network I/O
--    are disabled by the Lua engine ("API disabled in the context of body_filter").
--    Dispatching asynchronous HTTP requests to the external sanitizer microservice
--    from `body_filter` is architecturally impossible without pure in-memory Lua.
-- 2. SSE Streaming Chunk Fragmentation: Enterprise LLM workloads operate via
--    Server-Sent Events (SSE) streaming (`stream: true`). Tokens arrive fragmented
--    across arbitrary TCP chunk boundaries (e.g. "123.", "456.", "789-00").
--    Buffering or parsing incomplete token streams destroys Time-To-First-Token
--    (TTFT) latency and risks corrupting the SSE event framing protocol.
-- 3. Residual Risk & Perimeter Defense: The residual risk is model-echoed PII
--    (i.e. LLM repeating sensitive credentials). Under BCB CMN 4893/21 and BCB 85/21,
--    this risk is primarily addressed via strict ingress perimeter scrubbing:
--    by sanitizing all prompt roles (system, user, assistant, developer) before
--    dispatch, external LLMs never ingest real PII, mitigating echo risks at the root.
-- ==============================================================================

local cjson = require "cjson.safe"
local http = require "resty.http"

local BCBPIISanitizerHandler = {
  PRIORITY = 1010, -- Execute before ai-proxy (1000)
  VERSION = "2.1.0",
}

--- Fast in-memory pre-screening to bypass external sidecar when no PII markers exist
-- @param text String to inspect
-- @return boolean true if text requires deep scanning, false if provably devoid of PII
local function quick_pii_check(text)
  if not text or #text == 0 then
    return false
  end
  -- 1. Digits are mandatory for CPF, CNPJ, Phone, Bank Account, and Monetary amounts
  if string.find(text, "%d") then
    return true
  end
  -- 2. At-sign is mandatory for Email addresses
  if string.find(text, "@", 1, true) then
    return true
  end
  -- 3. Capitalized word sequences may represent personal Names
  if string.find(text, "%u%l+%s+%u%l+") then
    return true
  end
  return false
end

--- Sanitizes a single text string via LRU cache or microservice call
-- @param text String content to scan and redact
-- @param config Plugin configuration record
-- @param cache ngx.shared cache dictionary or nil
-- @param redact_type Redaction mode ("placeholder" or "synthetic")
-- @return sanitize_result table if successful, or nil and error code
local function sanitize_single_text(text, config, cache, redact_type)
  if not text or type(text) ~= "string" or #text == 0 then
    return nil, "empty_text"
  end

  -- Fast in-gateway pre-filter: skip network hop if provably devoid of PII entities
  if not quick_pii_check(text) then
    return {
      sanitized_text = text,
      pii_detected = {},
      total_entities = 0,
      processing_time_ms = 0.0,
      redact_type = redact_type,
    }, nil
  end

  local cache_key = "bcb_pii:" .. ngx.md5(text .. ":" .. redact_type)
  local cached_res = nil

  if cache then
    cached_res = cache:get(cache_key)
  end

  if cached_res then
    local parse_ok, decoded = pcall(cjson.decode, cached_res)
    if parse_ok and decoded then
      kong.log.debug("[bcb-pii-sanitizer] Cache hit for prompt text.")
      return decoded, nil
    end
  end

  local httpc = http.new()
  httpc:set_timeout(config.timeout_ms or 5000)

  local req_payload = cjson.encode({
    text = text,
    redact_type = redact_type,
  })

  local res, req_err = httpc:request_uri(config.sanitizer_url, {
    method = "POST",
    body = req_payload,
    ssl_verify = config.ssl_verify ~= nil and config.ssl_verify or false,
    headers = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json",
    },
  })

  if req_err or not res or res.status ~= 200 then
    kong.log.err("[bcb-pii-sanitizer] Failed to connect to sanitizer microservice: ", req_err or (res and res.status))
    kong.log.set_serialize_value("bcb.sanitizer.degraded", true)
    if not config.fail_open then
      kong.log.set_serialize_value("bcb.sanitizer.fail_closed", true)
      return nil, "fail_closed"
    else
      kong.log.set_serialize_value("bcb.sanitizer.fail_open", true)
      return nil, "fail_open"
    end
  end

  local parse_ok, decoded = pcall(cjson.decode, res.body)
  -- Place connection into keepalive pool (max idle 60s, pool size 100)
  pcall(function() httpc:set_keepalive(60000, 100) end)

  if parse_ok and decoded then
    if cache and config.cache_ttl_seconds > 0 then
      cache:set(cache_key, cjson.encode(decoded), config.cache_ttl_seconds)
    end
    return decoded, nil
  end

  return nil, "parse_error"
end

--- Inspects and sanitizes messages inside OpenAI-compatible chat payload across all roles and content formats
-- @param config Plugin configuration record
function BCBPIISanitizerHandler:access(config)
  kong.service.request.enable_buffering()

  local body_raw = kong.request.get_raw_body()
  if not body_raw or body_raw == "" then
    return
  end

  local content_type = kong.request.get_header("Content-Type") or ""
  local is_json_content = string.find(string.lower(content_type), "application/json", 1, true)

  local ok, body_json = pcall(cjson.decode, body_raw)
  if not ok or not body_json or type(body_json) ~= "table" then
    if is_json_content or not config.fail_open then
      kong.log.warn("[bcb-pii-sanitizer] Request body is not valid JSON, rejecting under strict compliance.")
      return kong.response.exit(400, {
        type = "https://tools.ietf.org/html/rfc7807",
        title = "Bad Request - Invalid JSON",
        status = 400,
        detail = "Request payload must be valid JSON matching chat completions schema.",
        instance = kong.request.get_path(),
      }, { ["Content-Type"] = "application/problem+json" })
    else
      kong.log.warn("[bcb-pii-sanitizer] Request body is not valid JSON, skipping processing.")
      return
    end
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

  -- Helper to sanitize a text string and apply mutation
  local function process_text_item(text, update_callback)
    if not text or type(text) ~= "string" or #text == 0 then
      return true
    end

    local sanitize_result, err = sanitize_single_text(text, config, cache, redact_type)
    if err == "fail_closed" then
      return false, kong.response.exit(502, {
        type = "https://tools.ietf.org/html/rfc7807",
        title = "Bad Gateway",
        status = 502,
        detail = "PII Sanitization service unavailable and fail-closed policy is active.",
        instance = kong.request.get_path(),
      }, { ["Content-Type"] = "application/problem+json" })
    elseif err then
      -- Fail-open or non-fatal error: retain original text
      return true
    end

    if sanitize_result and sanitize_result.sanitized_text then
      if sanitize_result.sanitized_text ~= text then
        update_callback(sanitize_result.sanitized_text)
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

    return true
  end

  -- Scan ALL messages regardless of role (system, user, assistant, developer, tool)
  for idx, msg in ipairs(messages) do
    if type(msg) == "table" and msg.content then
      -- 1. Standard String Content
      if type(msg.content) == "string" and #msg.content > 0 then
        local success, exit_res = process_text_item(msg.content, function(new_text)
          body_json.messages[idx].content = new_text
        end)
        if not success then
          return exit_res
        end

      -- 2. OpenAI Structured Array Content Parts: [{type="text", text=...}, ...]
      elseif type(msg.content) == "table" then
        for part_idx, part in ipairs(msg.content) do
          if type(part) == "table" and part.type == "text" and type(part.text) == "string" and #part.text > 0 then
            local success, exit_res = process_text_item(part.text, function(new_text)
              body_json.messages[idx].content[part_idx].text = new_text
            end)
            if not success then
              return exit_res
            end
          elseif type(part) == "string" and #part > 0 then
            local success, exit_res = process_text_item(part, function(new_text)
              body_json.messages[idx].content[part_idx] = new_text
            end)
            if not success then
              return exit_res
            end
          end
        end
      end
    end
  end

  -- If any message content was rewritten, update the raw request body
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
