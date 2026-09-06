export type InventoryImageKey = {
  readonly installation_id: string;
  readonly repository_id: string;
  readonly logical_image_ref: string;
};

export async function currentInventoryGeneration(
  database: D1Database,
  image: InventoryImageKey,
): Promise<number> {
  await database
    .prepare(
      `INSERT OR IGNORE INTO image_inventory_generations
       (installation_id,repository_id,logical_image_ref,generation,updated_at)
       VALUES (?,?,?,0,?)`,
    )
    .bind(image.installation_id, image.repository_id, image.logical_image_ref, Date.now())
    .run();
  return (
    (await database
      .prepare(
        `SELECT generation FROM image_inventory_generations
         WHERE installation_id=? AND repository_id=? AND logical_image_ref=?`,
      )
      .bind(image.installation_id, image.repository_id, image.logical_image_ref)
      .first<number>("generation")) ?? 0
  );
}
