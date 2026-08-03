terraform {
  required_version = ">= 1.8.0"
  backend "s3" {
    bucket                      = "tektum-tofu-state"
    region                      = "auto"
    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
  }
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 5.0" }
  }
}

variable "cloudflare_account_id" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production"
  }
}
variable "worker_bundle_path" { type = string }
variable "descope_issuer" {
  type    = string
  default = ""
}
variable "descope_discovery_url" {
  type    = string
  default = ""
}
variable "descope_audience" {
  type    = string
  default = ""
}
variable "descope_project_id" {
  type    = string
  default = ""
}
variable "descope_tenant_id" {
  type    = string
  default = ""
}
variable "osv_base_url" {
  type    = string
  default = "https://storage.googleapis.com/osv-vulnerabilities"
}
variable "dispatch_enabled" {
  type    = bool
  default = false
}

locals {
  worker_name           = "squawk-${var.environment}"
  descope_enabled       = var.descope_project_id != "" && var.descope_tenant_id != "" && var.descope_audience != ""
  descope_issuer        = coalesce(var.descope_issuer, "https://squawk.invalid")
  descope_discovery_url = coalesce(var.descope_discovery_url, "https://squawk.invalid/.well-known/openid-configuration")
  descope_audience      = var.descope_audience
  bindings = concat([
    { name = "DB", type = "d1", database_id = cloudflare_d1_database.squawk.id },
    { name = "DISPATCH_ENABLED", type = "plain_text", text = tostring(var.dispatch_enabled) },
    { name = "DESCOPE_AUDIENCE", type = "plain_text", text = local.descope_audience },
    { name = "DESCOPE_DISCOVERY_URL", type = "plain_text", text = local.descope_discovery_url },
    { name = "DESCOPE_ISSUER", type = "plain_text", text = local.descope_issuer },
    { name = "OSV_BASE_URL", type = "plain_text", text = var.osv_base_url }
  ])
}

resource "cloudflare_d1_database" "squawk" {
  account_id = var.cloudflare_account_id
  name       = local.worker_name
  read_replication = {
    mode = "disabled"
  }
}

resource "terraform_data" "descope" {
  count = local.descope_enabled ? 1 : 0
  triggers_replace = [
    filesha256("../scripts/provision-descope.ts"),
    var.descope_audience,
    var.descope_project_id,
    var.descope_tenant_id,
  ]
  input = {
    audience  = var.descope_audience
    project   = var.descope_project_id
    tenant_id = var.descope_tenant_id
  }
  provisioner "local-exec" {
    command = "bun ../scripts/provision-descope.ts"
    environment = {
      DESCOPE_AUDIENCE   = var.descope_audience
      DESCOPE_PROJECT_ID = var.descope_project_id
      DESCOPE_TENANT_ID  = var.descope_tenant_id
    }
  }
}

resource "cloudflare_workers_script" "squawk" {
  account_id         = var.cloudflare_account_id
  script_name        = local.worker_name
  content_file       = var.worker_bundle_path
  content_sha256     = filesha256(var.worker_bundle_path)
  main_module        = basename(var.worker_bundle_path)
  compatibility_date = "2026-08-01"
  bindings           = local.bindings
  observability = {
    enabled            = true
    head_sampling_rate = 1
    logs = {
      enabled         = true
      invocation_logs = true
      destinations    = ["cloudflare"]
    }
  }
  depends_on = [terraform_data.descope]
}

data "cloudflare_worker_versions" "latest" {
  account_id = var.cloudflare_account_id
  worker_id  = cloudflare_workers_script.squawk.id
  max_items  = 1
  depends_on = [cloudflare_workers_script.squawk]
}

resource "cloudflare_workers_deployment" "squawk" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_workers_script.squawk.script_name
  strategy    = "percentage"
  versions = [{
    percentage = 100
    version_id = data.cloudflare_worker_versions.latest.result[0].id
  }]
}

resource "cloudflare_workers_cron_trigger" "squawk" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_workers_script.squawk.script_name
  schedules   = [{ cron = "0 */4 * * *" }]
  depends_on  = [cloudflare_workers_deployment.squawk]
}

output "worker_name" { value = local.worker_name }
output "d1_database_id" { value = cloudflare_d1_database.squawk.id }
output "worker_version_id" { value = data.cloudflare_worker_versions.latest.result[0].id }
output "worker_configuration" {
  value = {
    d1_binding       = "DB"
    cron             = "0 */4 * * *"
    observability    = true
    dispatch_enabled = var.dispatch_enabled
  }
}
