DELETE FROM matching_errors
WHERE id NOT IN (
  SELECT MAX(id) FROM matching_errors GROUP BY component_id, vuln_id
);

CREATE UNIQUE INDEX idx_matching_errors_identity ON matching_errors(component_id, vuln_id);
