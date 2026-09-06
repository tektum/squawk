import type { Hono } from "hono";
import { z } from "zod";
import {
  ActionsAuthenticationError,
  ActionsAuthorizationError,
  authenticateActionsRun,
} from "./actions-oidc";
import { reconciliationReasons } from "./reconciliation-contract";
import { refreshReconciliationImage } from "./reconciliation-state";
import { enqueueReconciliations } from "./reconciliation-dispatch";
import { refreshFeedChecks } from "./sync";
import type { WorkerEnv } from "./worker-env";

const deliveryIdSchema = z.string().regex(/^[a-f0-9]{64}$/);
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const ackSchema = z.object({
  checkpoint_id: digestSchema,
  revision: z.number().int().positive(),
  payload_sha256: digestSchema,
});
const reasonSchema = z.enum(reconciliationReasons);

type DeliveryBinding = {
  readonly delivery_id: string;
  readonly installation_id: string;
  readonly repository_id: string;
  readonly logical_image_ref: string;
  readonly status: "dispatched" | "acked";
  readonly workflow_run_id: string;
  readonly attempt_id: string;
  readonly served_checkpoint_id: string | null;
  readonly served_revision: number | null;
  readonly served_payload_sha256: string | null;
  readonly workflow_ref_sha256: string;
};

async function deliveryBinding(
  database: D1Database,
  deliveryId: string,
): Promise<DeliveryBinding | null> {
  return database
    .prepare(
      `SELECT d.delivery_id,d.installation_id,d.repository_id,d.logical_image_ref,d.status,
        d.workflow_run_id,d.attempt_id,d.workflow_ref_sha256,d.served_checkpoint_id,
        d.served_revision,d.served_payload_sha256
       FROM reconciliation_deliveries d JOIN github_sources s
         ON s.installation_id=d.installation_id AND s.repository_id=d.repository_id
       WHERE d.delivery_id=? AND d.status IN ('dispatched','acked')
         AND d.workflow_run_id IS NOT NULL AND d.attempt_id IS NOT NULL
         AND d.workflow_ref_sha256 IS NOT NULL AND s.dispatch_schema_version=2`,
    )
    .bind(deliveryId)
    .first<DeliveryBinding>();
}

async function authorize(
  authorization: string | undefined,
  binding: DeliveryBinding,
): Promise<void> {
  await authenticateActionsRun(authorization, {
    repositoryId: binding.repository_id,
    runId: binding.workflow_run_id,
    workflowRefSha256: binding.workflow_ref_sha256,
  });
}

export function registerReconciliationRoutes(app: Hono<WorkerEnv>): void {
  app.get("/v1/actions/reconciliations/:deliveryId", async (context) => {
    const deliveryId = deliveryIdSchema.parse(context.req.param("deliveryId"));
    const binding = await deliveryBinding(context.env.DB, deliveryId);
    if (!binding || binding.status !== "dispatched")
      return context.json({ error: "reconciliation delivery not found" }, 404);
    await authorize(context.req.header("Authorization"), binding);
    const now = Date.now();
    await refreshFeedChecks(context.env.DB, now);
    await refreshReconciliationImage(
      context.env.DB,
      {
        installation_id: binding.installation_id,
        repository_id: binding.repository_id,
        logical_image_ref: binding.logical_image_ref,
      },
      now,
    );
    const state = await context.env.DB.prepare(
      `SELECT revision,state,reason,checkpoint_id FROM image_reconciliation_state
       WHERE installation_id=? AND repository_id=? AND logical_image_ref=?`,
    )
      .bind(binding.installation_id, binding.repository_id, binding.logical_image_ref)
      .first<{
        readonly revision: number;
        readonly state: "ready" | "blocked";
        readonly reason: string | null;
        readonly checkpoint_id: string;
      }>();
    if (!state) return context.json({ error: "reconciliation state not found" }, 404);
    if (state.state === "blocked")
      return context.json(
        {
          schema_version: 2 as const,
          state: "blocked" as const,
          delivery_id: deliveryId,
          revision: state.revision,
          reason: reasonSchema.parse(state.reason),
        },
        409,
      );
    const checkpoint = await context.env.DB.prepare(
      `SELECT payload_json,payload_sha256 FROM reconciliation_checkpoints
       WHERE checkpoint_id=? AND state='ready'`,
    )
      .bind(state.checkpoint_id)
      .first<{ readonly payload_json: string; readonly payload_sha256: string }>();
    if (!checkpoint) return context.json({ error: "reconciliation checkpoint not found" }, 404);
    const parsed = z.record(z.string(), z.unknown()).parse(JSON.parse(checkpoint.payload_json));
    const { checkpoint_id, revision, ...payload } = parsed;
    const served = await context.env.DB.prepare(
      `UPDATE reconciliation_deliveries SET served_checkpoint_id=?,served_revision=?,served_payload_sha256=?
       WHERE delivery_id=? AND status='dispatched' AND workflow_run_id=? AND attempt_id=?
         AND EXISTS (SELECT 1 FROM image_reconciliation_state r
           JOIN image_inventory_generations g ON g.installation_id=r.installation_id
             AND g.repository_id=r.repository_id AND g.logical_image_ref=r.logical_image_ref
           WHERE r.installation_id=reconciliation_deliveries.installation_id
             AND r.repository_id=reconciliation_deliveries.repository_id
             AND r.logical_image_ref=reconciliation_deliveries.logical_image_ref
             AND r.state='ready' AND r.revision=? AND r.checkpoint_id=?
             AND r.inventory_generation=g.generation)`,
    )
      .bind(
        state.checkpoint_id,
        state.revision,
        checkpoint.payload_sha256,
        deliveryId,
        binding.workflow_run_id,
        binding.attempt_id,
        state.revision,
        state.checkpoint_id,
      )
      .run();
    if (served.meta.changes !== 1)
      return context.json({ error: "reconciliation run superseded" }, 409);
    return context.json({
      schema_version: 2 as const,
      state: "ready" as const,
      checkpoint: {
        checkpoint_id,
        revision,
        payload_sha256: checkpoint.payload_sha256,
        ...payload,
      },
    });
  });

  app.post("/v1/actions/reconciliations/:deliveryId/ack", async (context) => {
    const deliveryId = deliveryIdSchema.parse(context.req.param("deliveryId"));
    const binding = await deliveryBinding(context.env.DB, deliveryId);
    if (!binding) return context.json({ error: "reconciliation delivery not found" }, 404);
    await authorize(context.req.header("Authorization"), binding);
    const acknowledgement = ackSchema.parse(await context.req.json());
    const exact =
      binding.served_checkpoint_id === acknowledgement.checkpoint_id &&
      binding.served_revision === acknowledgement.revision &&
      binding.served_payload_sha256 === acknowledgement.payload_sha256;
    if (!exact) return context.json({ error: "reconciliation acknowledgement mismatch" }, 409);
    if (binding.status === "acked") return context.body(null, 204);
    const now = Date.now();
    const results = await context.env.DB.batch([
      context.env.DB.prepare(
        `UPDATE reconciliation_deliveries SET status='acked',acked_at=?,error=NULL
           WHERE delivery_id=? AND status='dispatched' AND workflow_run_id=? AND attempt_id=?
             AND served_checkpoint_id=? AND served_revision=? AND served_payload_sha256=?
             AND EXISTS (SELECT 1 FROM image_reconciliation_state r
               JOIN image_inventory_generations g ON g.installation_id=r.installation_id
                 AND g.repository_id=r.repository_id AND g.logical_image_ref=r.logical_image_ref
               WHERE r.installation_id=reconciliation_deliveries.installation_id
                 AND r.repository_id=reconciliation_deliveries.repository_id
                 AND r.logical_image_ref=reconciliation_deliveries.logical_image_ref
                 AND r.state='ready' AND r.revision=? AND r.checkpoint_id=?
                 AND r.inventory_generation=g.generation)`,
      ).bind(
        now,
        deliveryId,
        binding.workflow_run_id,
        binding.attempt_id,
        acknowledgement.checkpoint_id,
        acknowledgement.revision,
        acknowledgement.payload_sha256,
        acknowledgement.revision,
        acknowledgement.checkpoint_id,
      ),
      context.env.DB.prepare(
        `UPDATE image_reconciliation_state SET applied_revision=?,updated_at=?
           WHERE installation_id=? AND repository_id=? AND logical_image_ref=?
             AND state='ready' AND revision=? AND checkpoint_id=?
             AND inventory_generation=(SELECT generation FROM image_inventory_generations g
               WHERE g.installation_id=image_reconciliation_state.installation_id
                 AND g.repository_id=image_reconciliation_state.repository_id
                 AND g.logical_image_ref=image_reconciliation_state.logical_image_ref)
             AND EXISTS (SELECT 1 FROM reconciliation_deliveries d
               WHERE d.delivery_id=? AND d.status='acked' AND d.acked_at=?
                 AND d.workflow_run_id=? AND d.attempt_id=?
                 AND d.served_checkpoint_id=? AND d.served_revision=?
                 AND d.served_payload_sha256=?)`,
      ).bind(
        acknowledgement.revision,
        now,
        binding.installation_id,
        binding.repository_id,
        binding.logical_image_ref,
        acknowledgement.revision,
        acknowledgement.checkpoint_id,
        deliveryId,
        now,
        binding.workflow_run_id,
        binding.attempt_id,
        acknowledgement.checkpoint_id,
        acknowledgement.revision,
        acknowledgement.payload_sha256,
      ),
    ]);
    if (results.some((result) => result.meta.changes !== 1))
      return context.json({ error: "reconciliation checkpoint superseded" }, 409);
    await enqueueReconciliations(context.env, now);
    return context.body(null, 204);
  });
}

export { ActionsAuthenticationError, ActionsAuthorizationError };
