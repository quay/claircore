-- This index is needed when deleting manifests, the cascade will want
-- to delete rows from manifest_index based on the manifest.id. Without
-- this index things get slow.
CREATE INDEX IF NOT EXISTS idx_manifest_index_manifest_id ON manifest_index(manifest_id);
