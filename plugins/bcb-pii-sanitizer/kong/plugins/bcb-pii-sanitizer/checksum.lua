-- ==============================================================================
-- Module: bcb-pii-sanitizer.checksum
-- Description: Pure Lua implementation of Brazilian national identifier Modulo-11
--              checksum algorithms (CPF, CNPJ) and ISO/IEC 7812 Luhn algorithm for
--              high-performance in-gateway pre-screening and fast-path bypass.
-- Compliance: Resolução CMN 4893/21 & BCB 85/21 / OWASP LLM02:2025
-- ==============================================================================

local _M = {}

--- Validates an 11-digit Brazilian CPF via Modulo-11
-- @param digits_str string of exactly 11 numeric characters
-- @return boolean true if mathematically valid CPF checksum, false otherwise
function _M.validate_cpf(digits_str)
  if not digits_str or #digits_str ~= 11 or not string.match(digits_str, "^%d%d%d%d%d%d%d%d%d%d%d$") then
    return false
  end

  -- Reject identical sequences ("00000000000" through "99999999999")
  local first_char = string.sub(digits_str, 1, 1)
  if digits_str == string.rep(first_char, 11) then
    return false
  end

  -- First check digit (D1)
  local s1 = 0
  for i = 1, 9 do
    local d = tonumber(string.sub(digits_str, i, i))
    s1 = s1 + d * (11 - i)
  end
  local r1 = 11 - (s1 % 11)
  local d1 = (r1 >= 10) and 0 or r1
  if tonumber(string.sub(digits_str, 10, 10)) ~= d1 then
    return false
  end

  -- Second check digit (D2)
  local s2 = 0
  for i = 1, 10 do
    local d = tonumber(string.sub(digits_str, i, i))
    s2 = s2 + d * (12 - i)
  end
  local r2 = 11 - (s2 % 11)
  local d2 = (r2 >= 10) and 0 or r2
  return tonumber(string.sub(digits_str, 11, 11)) == d2
end

--- Validates a 14-digit Brazilian CNPJ via Modulo-11
-- @param digits_str string of exactly 14 numeric characters
-- @return boolean true if mathematically valid CNPJ checksum, false otherwise
function _M.validate_cnpj(digits_str)
  if not digits_str or #digits_str ~= 14 or not string.match(digits_str, "^%d%d%d%d%d%d%d%d%d%d%d%d%d%d$") then
    return false
  end

  -- Reject identical sequences ("00000000000000" through "99999999999999")
  local first_char = string.sub(digits_str, 1, 1)
  if digits_str == string.rep(first_char, 14) then
    return false
  end

  local weights1 = { 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 }
  local s1 = 0
  for i = 1, 12 do
    local d = tonumber(string.sub(digits_str, i, i))
    s1 = s1 + d * weights1[i]
  end
  local r1 = s1 % 11
  local d1 = (r1 < 2) and 0 or (11 - r1)
  if tonumber(string.sub(digits_str, 13, 13)) ~= d1 then
    return false
  end

  local weights2 = { 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 }
  local s2 = 0
  for i = 1, 13 do
    local d = tonumber(string.sub(digits_str, i, i))
    s2 = s2 + d * weights2[i]
  end
  local r2 = s2 % 11
  local d2 = (r2 < 2) and 0 or (11 - r2)
  return tonumber(string.sub(digits_str, 14, 14)) == d2
end

--- Validates a Payment Card PAN (13 to 19 digits) via ISO/IEC 7812 Luhn Mod-10
-- @param digits_str string of 13 to 19 numeric characters
-- @return boolean true if mathematically valid Luhn checksum, false otherwise
function _M.validate_luhn(digits_str)
  if not digits_str or #digits_str < 13 or #digits_str > 19 or not string.match(digits_str, "^%d+$") then
    return false
  end

  local first_char = string.sub(digits_str, 1, 1)
  if digits_str == string.rep(first_char, #digits_str) then
    return false
  end

  local total = 0
  local parity = 0
  for i = #digits_str, 1, -1 do
    local d = tonumber(string.sub(digits_str, i, i))
    if parity % 2 == 1 then
      local doubled = d * 2
      total = total + ((doubled > 9) and (doubled - 9) or doubled)
    else
      total = total + d
    end
    parity = parity + 1
  end

  return (total % 10) == 0
end

--- High-performance in-memory pre-screening scanner.
-- Determines whether a prompt string contains any candidate Brazilian PII entities
-- (CPF, CNPJ, Payment Card, PIX Key, Bank Account, Phone, Email, RG, Name, Money).
-- If provably clean, the gateway fast-paths the request, skipping the external sidecar.
-- @param text String content to evaluate
-- @return boolean true if deep scanning required, false if provably devoid of PII
function _M.quick_pii_check(text)
  if not text or type(text) ~= "string" or #text == 0 then
    return false
  end

  -- 1. Email check: presence of '@' with alphanumeric surround
  if string.find(text, "@", 1, true) then
    if string.match(text, "[%w%.%_%+-]+@[%w%.%_%+-]+%.%a+") then
      return true
    end
  end

  -- 2. Currency check: R$, BRL, US$, $, EUR followed by numbers
  if string.find(text, "R%$") or string.find(text, "BRL") or string.find(text, "US%$") or string.find(text, "%$") then
    if string.match(text, "(?i)R?%$%s?%d") or string.match(text, "(?i)BRL%s?%d") then
      return true
    end
  end

  -- 3. Bank Account trigger keywords
  local lower_text = string.lower(text)
  if string.find(lower_text, "agencia") or string.find(lower_text, "agência")
     or string.find(lower_text, "conta") or string.find(lower_text, "c/c")
     or string.find(lower_text, "poupanca") or string.find(lower_text, "poupança")
     or string.find(lower_text, "ag:") or string.find(lower_text, "cc:") then
    return true
  end

  -- 4. PIX Key indicators (EVP UUID pattern or explicit PIX keywords)
  if string.find(lower_text, "pix") or string.find(lower_text, "evp") or string.find(lower_text, "chave") then
    return true
  end
  if string.match(text, "%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x") then
    return true
  end

  -- 5. Brazilian RG format (XX.XXX.XXX-X or X.XXX.XXX-X)
  if string.match(text, "%d+%.%d%d%d%.%d%d%d%-[%dxX]") then
    return true
  end

  -- 6. Formatted Phone Number (e.g. (11) 98765-4321 or (11) 3456-7890)
  if string.match(text, "%(%d%d%)%s?%d%d%d%d+%-?%d%d%d%d") then
    return true
  end

  -- 7. Formatted Documents (CPF, CNPJ, Card)
  -- Formatted CPF: XXX.XXX.XXX-XX
  for d1, d2, d3, d4 in string.gmatch(text, "(%d%d%d)%.(%d%d%d)%.(%d%d%d)%-(%d%d)") do
    local raw = d1 .. d2 .. d3 .. d4
    if _M.validate_cpf(raw) then
      return true
    end
  end

  -- Formatted CNPJ: XX.XXX.XXX/XXXX-XX
  for d1, d2, d3, d4, d5 in string.gmatch(text, "(%d%d)%.(%d%d%d)%.(%d%d%d)/(%d%d%d%d)%-(%d%d)") do
    local raw = d1 .. d2 .. d3 .. d4 .. d5
    if _M.validate_cnpj(raw) then
      return true
    end
  end

  -- Formatted Card: XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX
  for p1, p2, p3, p4 in string.gmatch(text, "(%d%d%d%d)[%s%-](%d%d%d%d)[%s%-](%d%d%d%d)[%s%-](%d%d%d%d)") do
    local raw = p1 .. p2 .. p3 .. p4
    if _M.validate_luhn(raw) then
      return true
    end
  end

  -- 8. Contiguous Raw Number Sequences
  for seq in string.gmatch(text, "%d+") do
    local len = #seq
    if len == 11 then
      -- Unformatted CPF or 11-digit mobile phone
      if _M.validate_cpf(seq) then
        return true
      end
      -- Brazilian mobile format: DDD (11-99) followed by 9 and 8 digits
      local ddd = tonumber(string.sub(seq, 1, 2))
      local ninth = string.sub(seq, 3, 3)
      if ddd and ddd >= 11 and ddd <= 99 and ninth == "9" then
        return true
      end
    elseif len == 14 then
      -- Unformatted CNPJ
      if _M.validate_cnpj(seq) then
        return true
      end
    elseif len >= 13 and len <= 19 then
      -- Unformatted payment card (PAN)
      if _M.validate_luhn(seq) then
        return true
      end
    elseif len == 10 then
      -- Brazilian landline format: DDD (11-99) followed by 2-5 and 7 digits
      local ddd = tonumber(string.sub(seq, 1, 2))
      local first_digit = tonumber(string.sub(seq, 3, 3))
      if ddd and ddd >= 11 and ddd <= 99 and first_digit and first_digit >= 2 and first_digit <= 5 then
        return true
      end
    end
  end

  -- 9. Capitalized Name Sequences (%u%l+ %u%l+)
  if string.find(text, "%u%l+%s+%u%l+") then
    return true
  end

  -- Provably devoid of regulated PII entities: bypass sidecar hop
  return false
end

return _M
