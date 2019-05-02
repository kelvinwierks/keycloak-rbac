-- Grab pluginname from module name
local BasePlugin = require "kong.plugins.base_plugin"

-- load the base plugin object and create a subclass
--local access = require "kong.plugins.hello-world.access"


local KeycloakRBACHandler = BasePlugin:extend()

local kong = kong
local ngx_re_gmatch = ngx.re.gmatch
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"



local function retrieve_token(request, conf)

  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

local function check_token(conf)

  local token, err = retrieve_token(kong.request, conf)

  local token, err = retrieve_token(kong.request, conf)
  if err then
    kong.log.err(err)
    return false, {status = 500, message = err}

  end

  if not token then
    return false, {status = 401, message = "token required"}
  end

  local jwt, err = jwt_decoder:new(token)
  if err then
    kong.log.err(err)
    return false, {status = 500, message = err}
  end

  return jwt.claims
end

local function group_in_groups(groups_to_check, groups)
  
  for k,v in ipairs(groups_to_check) do
    for _,g in ipairs(groups) do
      if v == g then return true end
    end
  end
end

local function do_rbac_check(conf)

  local claims = check_token(conf)
  local service_name = kong.router.get_service()['name']

  local r = claims[conf.roles_claim_name]

  if r[service_name] then --- service name is in the JWT claims!!!
    local roles = r[service_name]['roles'] --roles within the JWT claim for this service name

    local access = false
    if next(conf.roles) ~= nil then
        access =  group_in_groups(roles, conf.roles)
    end

    kong.log.inspect(access)
    if access == true then return true
    else return false, {status = 403, message = "forbidden"} 
    end

  else
    return false, {status = 403, message = "forbidden"}
  end

  return false, {status = 500, message = "something went wrong"}
end

local function compare_realms_from_url_and_token(conf)
  -- get tenant/realm name from issuer in JWT token
  local claims = check_token(conf)
  local iss = claims['iss']
  local jwt_realm = iss:sub(iss:find("/[^/]*$") + 1)

 -- get tenant/realm name from url 
 local router_matches = ngx.ctx.router_matches
 local url_realm = router_matches.uri_captures['realm']

 if jwt_realm == url_realm then return true
else return false, {status = 500, message = "something went wrong with your realm"} end

end

-- constructor
function KeycloakRBACHandler:new()
  KeycloakRBACHandler.super.new(self, "keycloak-rbac")

  -- do initialization here, runs in the 'init_by_lua_block', before worker processes are forked

end


---[[ runs in the 'access_by_lua_block'
function KeycloakRBACHandler:access(conf)
  KeycloakRBACHandler.super.access(self)

  kong.log.err(conf.resource_name)

  if conf.resource_name ~= nil then --resource name exists, so lets rbac.
    local ok, err = do_rbac_check(conf)

    if err then
      return kong.response.exit(err.status, err.errors or { message = err.message })
    end
  end

  if conf.do_realms_check == "yes" then
    local ok, err = compare_realms_from_url_and_token(conf)

    if err then
      return kong.response.exit(err.status, err.errors or { message = err.message })
    end
  end
end

return KeycloakRBACHandler
