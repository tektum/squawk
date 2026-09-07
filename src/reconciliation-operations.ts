import type { TenantId } from "./domain";

export async function releaseQuarantinedReconciliation(
  database: D1Database,
  tenantId: TenantId,
  deliveryId: string,
  attemptId: string | null,
  workflowRunId: string | null,
): Promise<boolean> {
  const result = await database
    .prepare(
      `UPDATE reconciliation_deliveries
       SET status='pending',workflow_run_id=NULL,workflow_ref_sha256=NULL,
         served_checkpoint_id=NULL,served_revision=NULL,served_payload_sha256=NULL,
         attempt_id=NULL,attempted_at=NULL,error='operator released reconciliation delivery'
       WHERE delivery_id=? AND (
         (status='pending' AND error='workflow dispatch outcome unknown'
           AND attempt_id=? AND workflow_run_id IS NULL)
         OR (status='failed' AND attempt_id IS ? AND workflow_run_id IS ?)
       ) AND EXISTS (SELECT 1 FROM github_sources s
         WHERE s.installation_id=reconciliation_deliveries.installation_id
           AND s.repository_id=reconciliation_deliveries.repository_id AND s.org_id=?)`,
    )
    .bind(deliveryId, attemptId, attemptId, workflowRunId, tenantId)
    .run();
  return result.meta.changes === 1;
}
