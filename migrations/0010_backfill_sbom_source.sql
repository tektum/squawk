-- Images ingested before SBOMs recorded their publishing source carry no
-- installation or repository, so their findings can never route: dispatchPending
-- treats a row without both ids as unroutable.
--
-- The delivery receipt for the same index digest already holds that provenance.
-- Adopt it only when exactly one source published the digest, because a digest
-- published by two repositories must not route a finding to the wrong one.
UPDATE sboms
SET
  installation_id = (
    SELECT d.installation_id
    FROM github_deliveries d
    WHERE d.subject_digest = substr(logical_image_ref, instr(logical_image_ref, '@') + 1)
  ),
  repository_id = (
    SELECT d.repository_id
    FROM github_deliveries d
    WHERE d.subject_digest = substr(logical_image_ref, instr(logical_image_ref, '@') + 1)
  )
WHERE installation_id IS NULL
  AND (
    SELECT COUNT(DISTINCT d.installation_id || '/' || d.repository_id)
    FROM github_deliveries d
    WHERE d.subject_digest = substr(logical_image_ref, instr(logical_image_ref, '@') + 1)
  ) = 1;
