INSERT INTO indexer_metadata_update_operation (ref, updater, fingerprint) VALUES ($1::uuid, $2 , $3) RETURNING (id);
