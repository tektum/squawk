-- Images ingested before SBOMs recorded their publishing source carry no
-- installation or repository, so their findings can never route: dispatchPending
-- treats a row without both ids as unroutable.
--
-- The accepted delivery receipt for the same index digest already holds that
-- provenance, so adopt it under three conditions:
--   * the receipt was accepted - a rejected delivery never proved anything;
--   * its source belongs to the same organization as the SBOM, so another
--     tenant's repository cannot become this image's dispatch target;
--   * exactly one source in that organization published the digest, because
--     adopting either side of a shared digest could route a finding to a
--     repository that did not publish it.
-- Ambiguous digests keep null provenance and stay unroutable, which is the safe
-- outcome. Idempotent, and a no-op where no accepted receipts exist.
UPDATE sboms
SET
  installation_id = receipt.installation_id,
  repository_id = receipt.repository_id
FROM (
  SELECT
    d.subject_digest AS digest,
    src.org_id AS org_id,
    MIN(d.installation_id) AS installation_id,
    MIN(d.repository_id) AS repository_id,
    COUNT(DISTINCT d.installation_id || '/' || d.repository_id) AS sources
  FROM github_deliveries d
  JOIN github_sources src
    ON src.installation_id = d.installation_id
    AND src.repository_id = d.repository_id
  WHERE d.status = 'accepted'
  GROUP BY d.subject_digest, src.org_id
) AS receipt
WHERE sboms.installation_id IS NULL
  AND receipt.sources = 1
  AND receipt.org_id = sboms.org_id
  AND receipt.digest = substr(sboms.logical_image_ref, instr(sboms.logical_image_ref, '@') + 1);
