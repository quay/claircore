-- Force per-ecosystem OSV updaters to re-fetch and re-parse after filtering
-- affected entries to the dump's ecosystem. Multi-ecosystem advisories
-- previously produced cross-ecosystem vulnerability rows (e.g. npm ranges
-- under osv/pypi).
DELETE FROM update_operation
WHERE
  updater LIKE 'osv/%';

DELETE FROM vuln v1 USING vuln v2
LEFT JOIN uo_vuln uvl ON v2.id = uvl.vuln
WHERE
  uvl.vuln IS NULL
  AND v2.updater LIKE 'osv/%'
  AND v1.id = v2.id;
