export const reconciliationReasons = [
  "inventory_incomplete",
  "unsupported_coverage",
  "feed_incomplete",
  "feed_stale",
  "evaluation_stale",
  "checkpoint_invalidated",
  "retirement_unverified",
] as const;
export type ReconciliationReason = (typeof reconciliationReasons)[number];

type InventoryPayload = {
  readonly checkpoint_id: string;
  readonly revision: number;
  readonly logical_image_ref: string;
  readonly source: {
    readonly installation_id: string;
    readonly repository_id: string;
    readonly ingestion_delivery_id: string;
  };
  readonly kind: "inventory_snapshot";
  readonly coverage: {
    readonly status: "complete";
    readonly evaluated_at: number;
    readonly advisory_feed_checked_at: number;
    readonly feed_checkpoint_ids: readonly string[];
    readonly unsupported_components: readonly [];
  };
  readonly platforms: readonly {
    readonly platform: "linux/amd64" | "linux/arm64";
    readonly image_ref: string;
    readonly sbom_sha256: string;
    readonly indexed_at: number;
    readonly status: "complete";
  }[];
  readonly findings: readonly {
    readonly delivery_id: string;
    readonly package_name: string;
    readonly ecosystem: string;
    readonly version: string;
    readonly vuln_id: string;
    readonly severity: string | null;
    readonly platforms: readonly string[];
  }[];
};

export type InventoryCandidate =
  | {
      readonly state: "blocked";
      readonly reason: ReconciliationReason;
      readonly fingerprint: string;
      readonly generation: number;
    }
  | {
      readonly state: "ready";
      readonly fingerprint: string;
      readonly generation: number;
      readonly payload: Omit<InventoryPayload, "checkpoint_id" | "revision">;
    };
