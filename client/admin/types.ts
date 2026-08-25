export type Counts = Readonly<Record<string, number>>;

export type Me = {
  readonly tenant_id: string;
  readonly user_id: string | null;
  readonly capabilities: readonly string[];
};

export type Overview = {
  readonly totals: {
    readonly images: number;
    readonly retired_sboms: number;
    readonly components: number;
    readonly matchable_components: number;
    readonly findings: number;
    readonly undispatched_findings: number;
    readonly matching_errors: number;
    readonly vulnerabilities: number;
    readonly ecosystems: number;
    readonly ecosystems_cached_at: number | null;
    readonly latest_sbom_at: number | null;
    readonly latest_delivery_at: number | null;
  } | null;
  readonly sboms: Counts;
  readonly findings: Counts;
  readonly ingestion_jobs: Counts;
  readonly advisory_jobs: Counts;
  readonly dispatch_deliveries: Counts;
  readonly sync_cursors: readonly {
    readonly ecosystem: string;
    readonly last_synced_at: string;
    readonly continuation_id: string | null;
  }[];
};

export type Image = {
  readonly id: string;
  readonly image_ref: string;
  readonly logical_image_ref: string;
  readonly platform: string;
  readonly backfill_status: string;
  readonly backfill_attempted_at: number | null;
  readonly backfill_error: string | null;
  readonly created_at: number;
  readonly retired_at: number | null;
  readonly installation_id: string | null;
  readonly repository_id: string | null;
  readonly components: number;
  readonly findings: number;
};

export type Component = {
  readonly package_name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly purl: string;
  readonly matchable: number;
};

export type ImageFinding = {
  readonly vuln_id: string;
  readonly detected_at: number;
  readonly dispatched_at: number | null;
  readonly package_name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly severity: string | null;
  readonly summary: string | null;
};

export type Delivery = {
  readonly delivery_id: string;
  readonly status: string;
  readonly created_at: number;
  readonly completed_at: number | null;
  readonly subject_digest: string | null;
};

export type ImageDetail = {
  readonly image: Image;
  readonly components: readonly Component[];
  readonly findings: readonly ImageFinding[];
  readonly deliveries: readonly Delivery[];
};

export type Finding = {
  readonly sbom_id: string;
  readonly image_ref: string;
  readonly logical_image_ref: string;
  readonly platform: string;
  readonly package_name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly vuln_id: string;
  readonly severity: string | null;
  readonly summary: string | null;
  readonly detected_at: number;
  readonly dispatched_at: number | null;
  readonly vex_status: string | null;
  readonly vex_justification: string | null;
};

export type Jobs = {
  readonly ingestion: readonly {
    readonly subject_digest: string;
    readonly logical_image_ref: string;
    readonly status: string;
    readonly next_descriptor: number;
    readonly saw_spdx: number;
    readonly attempted_at: number | null;
    readonly error: string | null;
    readonly created_at: number;
  }[];
  readonly advisories: readonly {
    readonly job_id: string;
    readonly ecosystem: string;
    readonly advisory_id: string;
    readonly status: string;
    readonly attempted_at: number | null;
    readonly error: string | null;
  }[];
  readonly dispatch: readonly {
    readonly delivery_id: string;
    readonly logical_image_ref: string;
    readonly package_name: string;
    readonly vuln_id: string;
    readonly status: string;
    readonly attempted_at: number | null;
    readonly error: string | null;
    readonly created_at: number;
  }[];
  readonly matching_errors: readonly {
    readonly vuln_id: string;
    readonly reason: string;
    readonly created_at: number;
    readonly package_name: string;
    readonly ecosystem: string;
    readonly version: string;
  }[];
};

export type Source = {
  readonly installation_id: string;
  readonly repository_id: string;
  readonly dispatch_workflow: string | null;
  readonly dispatch_ref: string | null;
  readonly created_at: number;
  readonly sboms: number;
  readonly pending_jobs: number;
};
