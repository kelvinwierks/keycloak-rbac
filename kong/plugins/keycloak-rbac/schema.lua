return {
  no_consumer = true,
  fields = {
    roles = {type = "array"},
    roles_claim_name = {type = "string", default = "resource_access"},
    resource_name = {type = "string" },
    do_realms_check = { type = "string", default = "no" },
  }
}