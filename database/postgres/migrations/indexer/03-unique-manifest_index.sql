-- This migration truncates the manifest_index and scanned_manifest tables
-- and adds a unique index to manifest_index. This is required since the
-- manifest_index table currently bloats with duplicate records.
--
-- After this migration is complete manifests will need to be re-indexed
-- for notifications on these manifests to work correctly.
--
-- Index reports will still be served without a re-index being necessary.
LOCK manifest_index;
LOCK scanned_manifest;
TRUNCATE manifest_index;
TRUNCATE scanned_manifest;
CREATE UNIQUE INDEX manifest_index_unique ON manifest_index (package_id, COALESCE(dist_id, 0), COALESCE(repo_id, 0), manifest_id);
