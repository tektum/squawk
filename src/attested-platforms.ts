import type { IngestRequest } from "./repository";
import { WebhookError } from "./webhook-contract";

export async function reconcilePlatformRequests(
  database: D1Database,
  orgId: string,
  logicalImageRef: string,
  requests: readonly IngestRequest[],
): Promise<readonly IngestRequest[]> {
  const unique: IngestRequest[] = [];
  const identities = new Map<string, string>();
  for (const request of requests) {
    const identity = `${request.input.image_ref}\u0000${request.predicateSha256}`;
    const prior = identities.get(request.input.platform);
    if (prior && prior !== identity) throw new WebhookError(409, "conflicting platform submission");
    if (!prior) {
      identities.set(request.input.platform, identity);
      unique.push(request);
    }
  }
  const storedRows = await database
    .prepare(
      "SELECT id,platform,image_ref,predicate_sha256 FROM sboms WHERE org_id=? AND logical_image_ref=? AND retired_at IS NULL",
    )
    .bind(orgId, logicalImageRef)
    .all<{
      readonly id: string;
      readonly platform: string;
      readonly image_ref: string;
      readonly predicate_sha256: string;
    }>();
  const repairs: { readonly id: string; readonly platform: string; readonly imageRef: string }[] =
    [];
  for (const [platform, identity] of identities) {
    const separator = identity.indexOf("\u0000");
    if (separator <= 0 || separator === identity.length - 1)
      throw new WebhookError(409, "conflicting platform submission");
    const imageRef = identity.slice(0, separator);
    const predicateSha256 = identity.slice(separator + 1);
    const samePredicate = storedRows.results.filter(
      (row) => row.predicate_sha256 === predicateSha256,
    );
    if (samePredicate.length > 1) throw new WebhookError(409, "conflicting platform submission");
    const existing = samePredicate[0];
    if (existing) {
      if (existing.platform !== platform || existing.image_ref !== imageRef)
        repairs.push({ id: existing.id, platform, imageRef });
      continue;
    }
    const occupied = storedRows.results.find((row) => row.platform === platform);
    if (occupied) repairs.push({ id: "", platform, imageRef });
  }
  for (const repair of repairs) {
    const occupied = storedRows.results.filter(
      (row) => row.platform === repair.platform && row.id !== repair.id,
    );
    if (
      occupied.some((row) => {
        const move = repairs.find((candidate) => candidate.id === row.id);
        return !move || move.platform === repair.platform;
      })
    )
      throw new WebhookError(409, "conflicting platform submission");
  }
  if (repairs.some((repair) => repair.id === ""))
    throw new WebhookError(409, "conflicting platform submission");
  if (repairs.length > 0)
    await database.batch(
      repairs.map((repair) =>
        database
          .prepare("UPDATE sboms SET platform=?,image_ref=? WHERE id=?")
          .bind(repair.platform, repair.imageRef, repair.id),
      ),
    );
  return unique;
}

export async function assertPersistedPlatforms(
  database: D1Database,
  orgId: string,
  logicalImageRef: string,
  image: string,
  subjects: ReadonlyMap<"linux/amd64" | "linux/arm64", string>,
): Promise<void> {
  const persisted = await database
    .prepare(
      "SELECT platform,image_ref FROM sboms WHERE org_id=? AND logical_image_ref=? AND retired_at IS NULL",
    )
    .bind(orgId, logicalImageRef)
    .all<{ readonly platform: string; readonly image_ref: string }>();
  if (
    subjects.size !== 2 ||
    persisted.results.length !== 2 ||
    [...subjects].some(
      ([platform, digest]) =>
        !persisted.results.some(
          (row) => row.platform === platform && row.image_ref === `${image}@${digest}`,
        ),
    )
  )
    throw new WebhookError(409, "incomplete platform subjects");
}
