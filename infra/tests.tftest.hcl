mock_provider "cloudflare" {}

variables {
  cloudflare_account_id = "account-id"
  environment           = "staging"
  worker_bundle_path    = "fixtures/worker.js"
  descope_issuer        = "https://issuer.example"
  descope_discovery_url = "https://issuer.example/.well-known/openid-configuration"
  descope_audience      = "https://squawk.example/staging"
  descope_project_id    = "project-id"
  descope_tenant_id     = "tenant-id"
}

run "create_lifecycle" {
  command = plan
  assert {
    condition     = output.worker_name == "squawk-staging"
    error_message = "worker name drifted"
  }
  assert {
    condition     = cloudflare_workers_script.squawk.main_module == "worker.js"
    error_message = "Worker must deploy as an ES module"
  }
  assert {
    condition     = output.worker_configuration.d1_binding == "DB" && output.worker_configuration.cron == "0 */4 * * *"
    error_message = "D1 or cron wiring drifted"
  }
}

run "update_lifecycle" {
  command = plan
  variables { dispatch_enabled = true }
  assert {
    condition     = output.worker_configuration.dispatch_enabled
    error_message = "rollout flag did not update"
  }
}

run "no_op_lifecycle" {
  command = plan
  assert {
    condition     = output.worker_configuration.dispatch_enabled == false
    error_message = "dark deployment default drifted"
  }
}
