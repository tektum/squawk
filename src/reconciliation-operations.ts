import type { TenantId } from "./domain";

export async function releaseQuarantinedReconciliation(
  database: D1Database,
  tenantId: TenantId,
  deliveryId: string,
  attemptId: string,
): Promise<boolean> {
  const result = await database
    .prepare(
      `UPDATE reconciliation_deliveries
       SET attempt_id=NULL,attempted_at=NULL,error='operator released quarantined dispatch'
       WHERE delivery_id=? AND attempt_id=? AND status='pending' AND workflow_run_id IS NULL
         AND error='workflow dispatch outcome unknown'
         AND EXISTS (SELECT 1 FROM github_sources s
           WHERE s.installation_id=reconciliation_deliveries.installation_id
             AND s.repository_id=reconciliation_deliveries.repository_id AND s.org_id=?)`,
    )
    .bind(deliveryId, attemptId, tenantId)
    .run();
  return result.meta.changes === 1;
}
