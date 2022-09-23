-- manifest_index_unique is being used for the affected manifest
-- query so this index is currently surplus to requirements.
DROP INDEX IF EXISTS manifest_index_manifest_id_package_id_dist_id_repo_id_idx;
