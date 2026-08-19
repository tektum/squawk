# Infrastructure

OpenTofu provisions the Cloudflare D1 database, advisory queue and dead-letter queue,
Worker deployment, queue consumer, and cron schedule. Outbound dispatch is enabled by default.

## Commands

```sh
bun run format:infra
bun run check:infra
```

`check:infra` runs canonical formatting, backend-disabled initialization with the
committed provider lock, validation, mock-provider tests, a four-platform
provider-lock drift check, high/critical Trivy Terraform scanning, and this
generated-reference drift check. TFLint runs with `--force` as advisory only:
its compatibility contract is Terraform, while OpenTofu is the source of truth.
The provider-lock refresh intentionally needs registry network access; the rest
of the OpenTofu checks use the locked, initialized provider.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.8.0 |
| <a name="requirement_cloudflare"></a> [cloudflare](#requirement\_cloudflare) | ~> 5.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_cloudflare"></a> [cloudflare](#provider\_cloudflare) | 5.23.0 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [cloudflare_d1_database.squawk](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/d1_database) | resource |
| [cloudflare_queue.osv_advisories](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/queue) | resource |
| [cloudflare_queue.osv_advisories_dlq](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/queue) | resource |
| [cloudflare_queue_consumer.osv_advisories](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/queue_consumer) | resource |
| [cloudflare_worker.squawk](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/worker) | resource |
| [cloudflare_worker_version.squawk](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/worker_version) | resource |
| [cloudflare_workers_cron_trigger.squawk](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/workers_cron_trigger) | resource |
| [cloudflare_workers_deployment.squawk](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/workers_deployment) | resource |
| [terraform_data.descope](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_cloudflare_account_id"></a> [cloudflare\_account\_id](#input\_cloudflare\_account\_id) | n/a | `string` | n/a | yes |
| <a name="input_descope_audience"></a> [descope\_audience](#input\_descope\_audience) | n/a | `string` | `""` | no |
| <a name="input_descope_project_id"></a> [descope\_project\_id](#input\_descope\_project\_id) | n/a | `string` | `""` | no |
| <a name="input_descope_tenant_id"></a> [descope\_tenant\_id](#input\_descope\_tenant\_id) | n/a | `string` | `""` | no |
| <a name="input_dispatch_enabled"></a> [dispatch\_enabled](#input\_dispatch\_enabled) | n/a | `bool` | `true` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | n/a | yes |
| <a name="input_osv_api_url"></a> [osv\_api\_url](#input\_osv\_api\_url) | n/a | `string` | `"https://api.osv.dev"` | no |
| <a name="input_osv_base_url"></a> [osv\_base\_url](#input\_osv\_base\_url) | n/a | `string` | `"https://storage.googleapis.com/osv-vulnerabilities"` | no |
| <a name="input_worker_bundle_path"></a> [worker\_bundle\_path](#input\_worker\_bundle\_path) | n/a | `string` | n/a | yes |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_d1_database_id"></a> [d1\_database\_id](#output\_d1\_database\_id) | n/a |
| <a name="output_worker_configuration"></a> [worker\_configuration](#output\_worker\_configuration) | n/a |
| <a name="output_worker_name"></a> [worker\_name](#output\_worker\_name) | n/a |
| <a name="output_worker_version_id"></a> [worker\_version\_id](#output\_worker\_version\_id) | n/a |
<!-- END_TF_DOCS -->
