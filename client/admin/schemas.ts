import * as z from "zod/mini";

/* The panel treats its own API as an external boundary: a Worker response is parsed
   before it reaches a view, so a shape change surfaces as one readable error instead of
   a crash inside `.map()`. Types are inferred here so the contract has one definition. */

const counts = z.record(z.string(), z.number());

export const meSchema = z.object({
  tenant_id: z.string(),
  user_id: z.nullable(z.string()),
  capabilities: z.array(z.string()),
});

export const overviewSchema = z.object({
  totals: z.nullable(
    z.object({
      images: z.number(),
      retired_sboms: z.number(),
      components: z.number(),
      matchable_components: z.number(),
      findings: z.number(),
      undispatched_findings: z.number(),
      matching_errors: z.number(),
      vulnerabilities: z.number(),
      ecosystems: z.number(),
      ecosystems_cached_at: z.nullable(z.number()),
      latest_sbom_at: z.nullable(z.number()),
      latest_delivery_at: z.nullable(z.number()),
    }),
  ),
  sboms: counts,
  findings: counts,
  ingestion_jobs: counts,
  advisory_jobs: counts,
  dispatch_deliveries: counts,
  sync_cursors: z.array(
    z.object({
      ecosystem: z.string(),
      last_synced_at: z.string(),
      continuation_id: z.nullable(z.string()),
    }),
  ),
});

const imageSchema = z.object({
  id: z.string(),
  image_ref: z.string(),
  logical_image_ref: z.string(),
  platform: z.string(),
  backfill_status: z.string(),
  backfill_attempted_at: z.nullable(z.number()),
  backfill_error: z.nullable(z.string()),
  created_at: z.number(),
  retired_at: z.nullable(z.number()),
  installation_id: z.nullable(z.string()),
  repository_id: z.nullable(z.string()),
  components: z.number(),
  findings: z.number(),
});

export const imagesSchema = z.object({ images: z.array(imageSchema) });

const componentShape = z.object({
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
  purl: z.string(),
  matchable: z.number(),
});

const publicComponentShape = z.object({
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
  matchable: z.number(),
});

export const publicOverviewSchema = z.object({
  totals: z.object({
    images: z.number(),
    components: z.number(),
    matchable_components: z.number(),
    findings: z.number(),
    vulnerabilities: z.number(),
    ecosystems: z.number(),
    latest_sbom_at: z.nullable(z.number()),
  }),
  severity: counts,
});

export const publicImageSchema = z.object({
  image_ref: z.string(),
  platforms: z.nullable(z.string()),
  components: z.number(),
  findings: z.number(),
  status: z.string(),
  created_at: z.number(),
});
export const publicImagesSchema = z.object({ images: z.array(publicImageSchema) });

export const publicImageDetailSchema = z.object({
  platforms: z.array(
    z.object({
      image_ref: z.string(),
      platform: z.string(),
      status: z.string(),
      created_at: z.number(),
    }),
  ),
  components: z.array(publicComponentShape),
  findings: z.array(
    z.object({
      vuln_id: z.string(),
      package_name: z.string(),
      ecosystem: z.string(),
      version: z.string(),
      severity: z.nullable(z.string()),
      summary: z.nullable(z.string()),
      detected_at: z.number(),
    }),
  ),
});

export const imageDetailSchema = z.object({
  image: imageSchema,
  components: z.array(componentShape),
  findings: z.array(
    z.object({
      vuln_id: z.string(),
      detected_at: z.number(),
      dispatched_at: z.nullable(z.number()),
      package_name: z.string(),
      ecosystem: z.string(),
      version: z.string(),
      severity: z.nullable(z.string()),
      summary: z.nullable(z.string()),
    }),
  ),
  deliveries: z.array(
    z.object({
      delivery_id: z.string(),
      status: z.string(),
      created_at: z.number(),
      completed_at: z.nullable(z.number()),
      subject_digest: z.nullable(z.string()),
    }),
  ),
});

const findingSchema = z.object({
  sbom_id: z.string(),
  image_ref: z.string(),
  logical_image_ref: z.string(),
  platform: z.string(),
  package_name: z.string(),
  ecosystem: z.string(),
  version: z.string(),
  vuln_id: z.string(),
  severity: z.nullable(z.string()),
  summary: z.nullable(z.string()),
  detected_at: z.number(),
  dispatched_at: z.nullable(z.number()),
  vex_status: z.nullable(z.string()),
  vex_justification: z.nullable(z.string()),
});

export const findingsSchema = z.object({ findings: z.array(findingSchema) });

export const jobsSchema = z.object({
  ingestion: z.array(
    z.object({
      subject_digest: z.string(),
      logical_image_ref: z.string(),
      status: z.string(),
      next_descriptor: z.number(),
      saw_spdx: z.number(),
      attempted_at: z.nullable(z.number()),
      error: z.nullable(z.string()),
      created_at: z.number(),
    }),
  ),
  advisories: z.array(
    z.object({
      job_id: z.string(),
      ecosystem: z.string(),
      advisory_id: z.string(),
      status: z.string(),
      attempted_at: z.nullable(z.number()),
      error: z.nullable(z.string()),
    }),
  ),
  dispatch: z.array(
    z.object({
      delivery_id: z.string(),
      logical_image_ref: z.string(),
      package_name: z.string(),
      vuln_id: z.string(),
      status: z.string(),
      attempted_at: z.nullable(z.number()),
      error: z.nullable(z.string()),
      created_at: z.number(),
    }),
  ),
  matching_errors: z.array(
    z.object({
      vuln_id: z.string(),
      reason: z.string(),
      created_at: z.number(),
      package_name: z.string(),
      ecosystem: z.string(),
      version: z.string(),
    }),
  ),
});

export const sourcesSchema = z.object({
  sources: z.array(
    z.object({
      installation_id: z.string(),
      repository_id: z.string(),
      dispatch_workflow: z.nullable(z.string()),
      dispatch_ref: z.nullable(z.string()),
      created_at: z.number(),
      sboms: z.number(),
      pending_jobs: z.number(),
    }),
  ),
});

export type Me = z.infer<typeof meSchema>;
export type Overview = z.infer<typeof overviewSchema>;
export type Image = z.infer<typeof imageSchema>;
export type ImageDetail = z.infer<typeof imageDetailSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type Jobs = z.infer<typeof jobsSchema>;
export type PublicOverview = z.infer<typeof publicOverviewSchema>;
export type PublicImage = z.infer<typeof publicImageSchema>;
export type PublicImageDetail = z.infer<typeof publicImageDetailSchema>;
