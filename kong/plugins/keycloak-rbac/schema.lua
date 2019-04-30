return {
  no_consumer = true,
  fields = {
    roles = {type = "array", default = {}},
    roles_claim_name = {type = "string", default = "resource_access"},
    resource_name = {type = "string", required = true},
  }
}