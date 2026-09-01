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
variable "osv_api_url" {
  type    = string
  default = "https://api.osv.dev"
}
variable "dispatch_enabled" {
  type    = bool
  default = true
}
variable "descope_provisioning_enabled" {
  type    = bool
  default = false
}

# Descope provisioning is opt-in: a failure inside its local-exec provisioner fails
# the whole worker deploy, and its management routes are unverified against the live API.
locals {
  worker_name         = "squawk-${var.environment}"
  descope_enabled     = var.descope_provisioning_enabled && var.descope_project_id != "" && var.descope_tenant_id != ""
  advisory_queue_name = "${local.worker_name}-osv-advisories"
  advisory_dlq_name   = "${local.worker_name}-osv-advisories-dlq"
  dispatch_queue_name = "${local.worker_name}-finding-dispatch"
  dispatch_dlq_name   = "${local.worker_name}-finding-dispatch-dlq"
  worker_modules = concat(
    [{ name = basename(var.worker_bundle_path), content_file = var.worker_bundle_path, content_type = "application/javascript+module" }],
    [for name in fileset(dirname(var.worker_bundle_path), "*.wasm") : {
      name         = name
      content_file = "${dirname(var.worker_bundle_path)}/${name}"
      content_type = "application/wasm"
    }]
  )
  bindings = concat([
    { name = "DB", type = "d1", database_id = cloudflare_d1_database.squawk.id },
    { name = "DISPATCH_ENABLED", type = "plain_text", text = tostring(var.dispatch_enabled) },
    { name = "DESCOPE_PROJECT_ID", type = "plain_text", text = var.descope_project_id },
    { name = "OSV_API_URL", type = "plain_text", text = var.osv_api_url },
    { name = "OSV_BASE_URL", type = "plain_text", text = var.osv_base_url },
    { name = "OSV_ADVISORY_JOBS", type = "queue", queue_name = cloudflare_queue.osv_advisories.queue_name },
    { name = "FINDING_DISPATCH", type = "queue", queue_name = cloudflare_queue.finding_dispatch.queue_name }
  ])
}

resource "cloudflare_d1_database" "squawk" {
  account_id = var.cloudflare_account_id
  name       = local.worker_name
  read_replication = {
    mode = "disabled"
  }
}

resource "cloudflare_queue" "osv_advisories" {
  account_id = var.cloudflare_account_id
  queue_name = local.advisory_queue_name
}

resource "cloudflare_queue" "osv_advisories_dlq" {
  account_id = var.cloudflare_account_id
  queue_name = local.advisory_dlq_name
}

resource "cloudflare_queue" "finding_dispatch" {
  account_id = var.cloudflare_account_id
  queue_name = local.dispatch_queue_name
}

resource "cloudflare_queue" "finding_dispatch_dlq" {
  account_id = var.cloudflare_account_id
  queue_name = local.dispatch_dlq_name
}

resource "terraform_data" "descope" {
  count = local.descope_enabled ? 1 : 0
  triggers_replace = [
    filesha256("../scripts/provision-descope.ts"),
    var.descope_project_id,
    var.descope_tenant_id,
  ]
  input = {
    project   = var.descope_project_id
    tenant_id = var.descope_tenant_id
  }
  provisioner "local-exec" {
    command = "bun ../scripts/provision-descope.ts"
    environment = {
      DESCOPE_PROJECT_ID = var.descope_project_id
      DESCOPE_TENANT_ID  = var.descope_tenant_id
    }
  }
}

resource "cloudflare_worker" "squawk" {
  account_id = var.cloudflare_account_id
  name       = local.worker_name
  subdomain = {
    enabled          = true
    previews_enabled = false
  }
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

resource "cloudflare_worker_version" "squawk" {
  account_id         = var.cloudflare_account_id
  worker_id          = cloudflare_worker.squawk.id
  bindings           = local.bindings
  compatibility_date = "2026-08-01"
  main_module        = basename(var.worker_bundle_path)
  modules            = local.worker_modules
}

resource "cloudflare_workers_deployment" "squawk" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_worker.squawk.name
  strategy    = "percentage"
  versions = [{
    percentage = 100
    version_id = cloudflare_worker_version.squawk.id
  }]
}

resource "cloudflare_queue_consumer" "osv_advisories" {
  account_id        = var.cloudflare_account_id
  queue_id          = cloudflare_queue.osv_advisories.id
  script_name       = cloudflare_worker.squawk.name
  type              = "worker"
  dead_letter_queue = cloudflare_queue.osv_advisories_dlq.queue_name
  settings = {
    batch_size       = 10
    max_concurrency  = 10
    max_retries      = 3
    max_wait_time_ms = 5000
    retry_delay      = 60
  }
  depends_on = [cloudflare_workers_deployment.squawk]
}

resource "cloudflare_queue_consumer" "finding_dispatch" {
  account_id        = var.cloudflare_account_id
  queue_id          = cloudflare_queue.finding_dispatch.id
  script_name       = cloudflare_worker.squawk.name
  type              = "worker"
  dead_letter_queue = cloudflare_queue.finding_dispatch_dlq.queue_name
  settings = {
    batch_size       = 3
    max_concurrency  = 10
    max_retries      = 3
    max_wait_time_ms = 5000
    retry_delay      = 30
  }
  depends_on = [cloudflare_workers_deployment.squawk]
}

resource "cloudflare_queue_consumer" "osv_advisories_dlq" {
  account_id  = var.cloudflare_account_id
  queue_id    = cloudflare_queue.osv_advisories_dlq.id
  script_name = cloudflare_worker.squawk.name
  type        = "worker"
  settings = {
    batch_size       = 10
    max_concurrency  = 1
    max_retries      = 1
    max_wait_time_ms = 5000
  }
  depends_on = [cloudflare_workers_deployment.squawk]
}

resource "cloudflare_queue_consumer" "finding_dispatch_dlq" {
  account_id  = var.cloudflare_account_id
  queue_id    = cloudflare_queue.finding_dispatch_dlq.id
  script_name = cloudflare_worker.squawk.name
  type        = "worker"
  settings = {
    batch_size       = 10
    max_concurrency  = 1
    max_retries      = 1
    max_wait_time_ms = 5000
  }
  depends_on = [cloudflare_workers_deployment.squawk]
}

resource "cloudflare_workers_cron_trigger" "squawk" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_worker.squawk.name
  schedules   = [{ cron = "0 */4 * * *" }]
  depends_on  = [cloudflare_workers_deployment.squawk]
}

output "worker_name" { value = local.worker_name }
output "d1_database_id" { value = cloudflare_d1_database.squawk.id }
output "worker_version_id" { value = cloudflare_worker_version.squawk.id }
output "worker_configuration" {
  value = {
    d1_binding       = "DB"
    cron             = "0 */4 * * *"
    observability    = true
    advisory_queue   = cloudflare_queue.osv_advisories.queue_name
    dispatch_enabled = var.dispatch_enabled
  }
}
