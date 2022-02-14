local urlparse = require("socket.url")
local http = require("socket.http")
JSON = (loadfile "JSON.lua")()

local item_dir = os.getenv("item_dir")
local item_name = os.getenv("item_name")
local custom_items = os.getenv("custom_items")
local warc_file_base = os.getenv("warc_file_base")

local url_count = 0
local downloaded = {}
local abortgrab = false
local exit_url = false

if urlparse == nil or http == nil then
  io.stdout:write("socket not corrently installed.\n")
  io.stdout:flush()
  abortgrab = true
end

local urls = {}
for url in string.gmatch(item_name, "([^\n]+)") do
  urls[string.lower(url)] = true
end

local status_code = nil

local redirect_urls = {}
local visited_urls = {}

local current_url = nil
local bad_urls = {}
local bad_params = {}
local item_first_url = nil
local redirect_domains = {}
local checked_domains = {}

local queued_urls = {}
local queued_outlinks = {}

local bad_params_file = io.open("bad-params.txt", "r")
for param in bad_params_file:lines() do
  local param = string.gsub(
    param, "([a-zA-Z])",
    function(c)
      return "[" .. string.lower(c) .. string.upper(c) .. "]"
    end
  )
  table.insert(bad_params, param)
end
bad_params_file:close()

read_file = function(file, bytes)
  if not bytes then
    bytes = "*all"
  end
  if file then
    local f = assert(io.open(file))
    local data = f:read(bytes)
    f:close()
    if not data then
      data = ""
    end
    return data
  else
    return ""
  end
end

check_domain_outlinks = function(url, target)
  local parent = string.match(url, "^https?://([^/]+)")
  while parent do
    if target and parent == target then
      return parent
    end
    parent = string.match(parent, "^[^%.]+%.(.+)$")
  end
  return false
end

bad_code = function(status_code)
  return status_code == 0
    or status_code < 200
    or (status_code > 200 and status_code < 300)
    or status_code == 400
    or status_code == 401
    or status_code == 403
    or status_code == 407
    or status_code == 408
    or status_code == 411
    or status_code == 413
    or status_code == 429
    or status_code == 451
    or status_code >= 500
end

find_path_loop = function(url, max_repetitions)
  local tested = {}
  for s in string.gmatch(urlparse.unescape(url), "([^/]+)") do
    s = string.lower(s)
    if not tested[s] then
      if s == "" then
        tested[s] = -2
      else
        tested[s] = 0
      end
    end
    tested[s] = tested[s] + 1
    if tested[s] == max_repetitions then
      return true
    end
  end
  return false
end

percent_encode_url = function(url)
  temp = ""
  for c in string.gmatch(url, "(.)") do
    local b = string.byte(c)
    if b < 32 or b > 126 then
      c = string.format("%%%02X", b)
    end
    temp = temp .. c
  end
  return temp
end

queue_url = function(urls_queue, url)
  url = percent_encode_url(url)
  url = string.match(url, "^([^{]+)")
  url = string.match(url, "^([^<]+)")
  url = string.match(url, "^([^\\]+)")
  if not queued_urls[url] and not urls_queue[url] then
    if find_path_loop(url, 3) then
      return false
    end
    urls_queue[url] = true
  end
end

remove_param = function(url, param_pattern)
  local newurl = url
  repeat
    url = newurl
    newurl = string.gsub(url, "([%?&;])" .. param_pattern .. "=[^%?&;]*[%?&;]?", "%1")
  until newurl == url
  return string.match(newurl, "^(.-)[%?&;]?$")
end

queue_new_urls = function(url)
  if string.match(url, "^https?://[^/]+/%(S%([a-z0-9A-Z]+%)%)") then
    return nil
  end
  local newurl = string.gsub(url, "([%?&;])[aA][mM][pP];", "%1")
  if url == current_url then
    if newurl ~= url then
      queue_url(queued_urls, newurl)
    end
  end
  for _, param_pattern in pairs(bad_params) do
    newurl = remove_param(newurl, param_pattern)
  end
  for s in string.gmatch(string.lower(newurl), "([a-f0-9]+)") do
    if string.len(s) == 32 then
      return nil
    end
  end
  if newurl ~= url then
    queue_url(queued_urls, newurl)
  end
  newurl = string.match(newurl, "^([^%?&]+)")
  if newurl ~= url then
    queue_url(queued_urls, newurl)
  end
end

report_bad_url = function(url)
  if current_url ~= nil then
    bad_urls[current_url] = true
  else
    bad_urls[string.lower(url)] = true
  end
end

wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict, reason)
  local url = urlpos["url"]["url"]
  local parenturl = parent["url"]
  local extract_page_requisites = false

print(url)

  if redirect_urls[parenturl] then
    return true
  end

  if find_path_loop(url, 3) then
    return false
  end

  local _, count = string.gsub(url, "[/%?]", "")
  if count >= 16 then
    return false
  end

  --[[if string.match(url, "%.pdf") and not string.match(parenturl, "%.pdf") then
    queue_url(url)
    return false
  end

  local domain_match = checked_domains[item_first_url]
  if not domain_match then
    domain_match = check_domain_outlinks(item_first_url)
    if not domain_match then
      domain_match = "none"
    end
    checked_domains[item_first_url] = domain_match
  end
  if domain_match ~= "none" then
    extract_page_requisites = true
    local newurl_domain = string.match(url, "^https?://([^/]+)")
    local to_queue = true
    for domain, _ in pairs(redirect_domains) do
      if check_domain_outlinks(url, domain) then
        to_queue = false
        break
      end
    end
    if to_queue then
      queue_url(url)
      return false
    end
  end]]

  --[[if (status_code < 200 or status_code >= 300) then
    return false
  end]]

  if urlpos["link_refresh_p"] ~= 0 then
    queue_url(queued_urls, url)
    return false
  end

  if urlpos["link_inline_p"] ~= 0 then
    queue_url(queued_urls, url)
    return false
  end

  if string.match(url, "^https?://[^/]+$") then
    url = url .. "/"
  end

  if string.match(url, "^https?://[^/]+%.ua/") then
    queue_url(queued_urls, url)
  else
    queue_url(queued_outlinks, url)
  end
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  local html = nil

  if url then
    downloaded[url] = true
  end

  local function check(url, headers)
    local url = string.match(url, "^([^#]+)")
    url = string.gsub(url, "&amp;", "&")
    queue_url(queued_urls, url)
  end

  local function checknewurl(newurl, headers)
    if string.match(newurl, "^#") then
      return nil
    end
    if string.match(newurl, "\\[uU]002[fF]") then
      return checknewurl(string.gsub(newurl, "\\[uU]002[fF]", "/"), headers)
    end
    if string.match(newurl, "^https?:////") then
      check(string.gsub(newurl, ":////", "://"), headers)
    elseif string.match(newurl, "^https?://") then
      check(newurl, headers)
    elseif string.match(newurl, "^https?:\\/\\?/") then
      check(string.gsub(newurl, "\\", ""), headers)
    elseif not url then
      return nil
    elseif string.match(newurl, "^\\/") then
      checknewurl(string.gsub(newurl, "\\", ""), headers)
    elseif string.match(newurl, "^//") then
      check(urlparse.absolute(url, newurl), headers)
    elseif string.match(newurl, "^/") then
      check(urlparse.absolute(url, newurl), headers)
    elseif string.match(newurl, "^%.%./") then
      if string.match(url, "^https?://[^/]+/[^/]+/") then
        check(urlparse.absolute(url, newurl), headers)
      else
        checknewurl(string.match(newurl, "^%.%.(/.+)$"), headers)
      end
    elseif string.match(newurl, "^%./") then
      check(urlparse.absolute(url, newurl), headers)
    end
  end

  local function checknewshorturl(newurl, headers)
    if string.match(newurl, "^#") then
      return nil
    end
    if url and string.match(newurl, "^%?") then
      check(urlparse.absolute(url, newurl), headers)
    elseif url and not (string.match(newurl, "^https?:\\?/\\?//?/?")
      or string.match(newurl, "^[/\\]")
      or string.match(newurl, "^%./")
      or string.match(newurl, "^[jJ]ava[sS]cript:")
      or string.match(newurl, "^[mM]ail[tT]o:")
      or string.match(newurl, "^vine:")
      or string.match(newurl, "^android%-app:")
      or string.match(newurl, "^ios%-app:")
      or string.match(newurl, "^%${")) then
      check(urlparse.absolute(url, newurl), headers)
    else
      checknewurl(newurl, headers)
    end
  end

  if not url then
    html = read_file(file)
    if not url then
      html = string.gsub(html, "&#160;", " ")
      html = string.gsub(html, "&lt;", "<")
      html = string.gsub(html, "&gt;", ">")
      html = string.gsub(html, "&quot;", '"')
      html = string.gsub(html, "&apos;", "'")
      html = string.gsub(html, "&#(%d+);",
        function(n)
          return string.char(n)
        end
      )
      html = string.gsub(html, "&#x(%d+);",
        function(n)
          return string.char(tonumber(n, 16))
        end
      )
      local temp_html = string.gsub(html, "\n", "")
      for _, remove in pairs({"", "<br/>", "</?p[^>]*>"}) do
        if remove ~= "" then
          temp_html = string.gsub(temp_html, remove, "")
        end
        for newurl in string.gmatch(temp_html, "(https?://[^%s<>#\"'\\`{})%]]+)") do
          while string.match(newurl, "[%.&,!;]$") do
            newurl = string.match(newurl, "^(.+).$")
          end
          check(newurl)
        end
      end
    end
    for newurl in string.gmatch(html, "[^%-][hH][rR][eE][fF]='([^']+)'") do
      checknewshorturl(newurl)
    end
    for newurl in string.gmatch(html, '[^%-][hH][rR][eE][fF]="([^"]+)"') do
      checknewshorturl(newurl)
    end
    for newurl in string.gmatch(string.gsub(html, "&[qQ][uU][oO][tT];", '"'), '"(https?://[^"]+)') do
      checknewurl(newurl)
    end
    for newurl in string.gmatch(string.gsub(html, "&#039;", "'"), "'(https?://[^']+)") do
      checknewurl(newurl)
    end
    if url then
      for newurl in string.gmatch(html, ">%s*([^<%s]+)") do
        checknewurl(newurl)
      end
    end
    --[[for newurl in string.gmatch(html, "%(([^%)]+)%)") do
      checknewurl(newurl)
    end]]
  elseif string.match(url, "^https?://[^/]+/.*[^a-z0-9A-Z][pP][dD][fF]$")
    or string.match(url, "^https?://[^/]+/.*[^a-z0-9A-Z][pP][dD][fF][^a-z0-9A-Z]")
    or string.match(read_file(file, 4), "%%[pP][dD][fF]") then
    io.stdout:write("Extracting links from PDF.\n")
    io.stdout:flush()
    local temp_file = file .. "-html.html"
    local check_file = io.open(temp_file)
    if check_file then
      check_file:close()
      os.remove(temp_file)
    end
    os.execute("pdftohtml -nodrm -hidden -i -s -q " .. file)
    check_file = io.open(temp_file)
    if check_file then
      check_file:close()
      wget.callbacks.get_urls(temp_file, nil, nil, nil)
      os.remove(temp_file)
    else
      io.stdout:write("Not a PDF.\n")
      io.stdout:flush()
    end
  end
end

wget.callbacks.write_to_warc = function(url, http_stat)
  local url_lower = string.lower(url["url"])
  if urls[url_lower] then
    current_url = url_lower
  end
  if bad_code(http_stat["statcode"]) then
    return false
  end
  if string.match(url["url"], "^https?://[^/]*ukr%.net/news/details/") then
    local html = read_file(http_stat["local_file"])
    if not string.match(html, '<meta%s+http%-equiv="refresh"%s+content="0;URL=https?://[^"]+"') then
      io.stdout:write("Got a bad page.\n")
      io.stdout:flush()
      report_bad_url(url["url"])
      return false
    end
  end
  return true
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  status_code = http_stat["statcode"]

  local url_lower = string.lower(url["url"])
  if urls[url_lower] then
    current_url = url_lower
  end

  url_count = url_count + 1
  io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. "  \n")
  io.stdout:flush()

  if redirect_domains["done"] then
    redirect_domains = {}
    redirect_urls = {}
    visited_urls = {}
    item_first_url = nil
  end
  redirect_domains[string.match(url["url"], "^https?://([^/]+)")] = true
  if not item_first_url then
    item_first_url = url["url"]
  end

  visited_urls[url["url"]] = true

  if exit_url then
    exit_url = false
    return wget.actions.EXIT
  end

  if status_code >= 300 and status_code <= 399 then
    local newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    redirect_urls[url["url"]] = true
    if downloaded[newloc] or newloc == "https://www.ukr.net/news/auto.html" then
      return wget.actions.EXIT
    end
  else
    redirect_domains["done"] = true
  end

  if downloaded[url["url"]] then
    return wget.actions.EXIT
  end

  if status_code >= 200 and status_code <= 399 then
    downloaded[url["url"]] = true
  end

  if status_code >= 200 and status_code < 300 then
    queue_new_urls(url["url"])
  end

  if bad_code(status_code) then
    io.stdout:write("Server returned " .. http_stat.statcode .. " (" .. err .. ").\n")
    io.stdout:flush()
    report_bad_url(url["url"])
    return wget.actions.EXIT
  end

  local sleep_time = 0

  if sleep_time > 0.001 then
    os.execute("sleep " .. sleep_time)
  end

  return wget.actions.NOTHING
end

wget.callbacks.finish = function(start_time, end_time, wall_time, numurls, total_downloaded_bytes, total_download_time)
  for key, items_data in pairs({
    ["ua-jdkigggz336884n"]=queued_urls,
    ["ua-urls-l1e4pjgn5uxre5y"]=queued_outlinks
  }) do
    local name = string.match(key, "^(.+)%-[^%-]+$")
    io.stdout:write("Queuing URLs for " .. name .. ".\n")
    io.stdout:flush()
    local newurls = nil
    for url, _ in pairs(items_data) do
      io.stdout:write("Queuing URL " .. url .. ".\n")
      io.stdout:flush()
      if newurls == nil then
        newurls = url
      else
        newurls = newurls .. "\0" .. url
      end
    end
    if newurls ~= nil then
      local tries = 0
      while tries < 10 do
        local body, code, headers, status = http.request(
          "http://blackbird-amqp.meo.ws:23038/" .. key .. "/",
          newurls
        )
        if code == 200 or code == 409 then
          io.stdout:write("Submitted discovered URLs.\n")
          io.stdout:flush()
          break
        end
        io.stdout:write("Failed to submit discovered URLs." .. tostring(code) .. tostring(body) .. "\n")
        io.stdout:flush()
        os.execute("sleep " .. math.floor(math.pow(2, tries)))
        tries = tries + 1
      end
      if tries == 12 then
        abortgrab = true
      end
    end
  end

  local file = io.open(item_dir .. '/' .. warc_file_base .. '_bad-urls.txt', 'w')
  for url, _ in pairs(bad_urls) do
    file:write(url .. "\n")
  end
  file:close()
end

wget.callbacks.before_exit = function(exit_status, exit_status_string)
  if abortgrab then
    return wget.exits.IO_FAIL
  end
  return exit_status
end

