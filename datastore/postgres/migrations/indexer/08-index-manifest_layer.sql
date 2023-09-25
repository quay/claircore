-- This index is needed when deleting manifests, we need to be able
-- to query only by layer_id to find layers that are also associated
-- with manifests other than the one being deleted.
CREATE INDEX IF NOT EXISTS manifest_layer_layer_idx ON manifest_layer (layer_id);
