-- Force per-ecosystem OSV updaters to re-fetch and re-parse after filtering
-- affected entries to the dump's ecosystem. Multi-ecosystem advisories
-- previously produced cross-ecosystem vulnerability rows (e.g. npm ranges
-- under osv/pypi).
--
-- Clear fingerprints rather than deleting update_operations so matching keeps
-- serving the existing (possibly imperfect) set until the next successful
-- update, instead of a vulns → empty → vulns gap. Stale cross-ecosystem rows
-- drop off once the new update_operation becomes latest; GC removes them later.
UPDATE update_operation
SET
  fingerprint = ''
WHERE
  updater LIKE 'osv/%';
