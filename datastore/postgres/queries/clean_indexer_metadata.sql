DELETE FROM indexer_metadata_update_operation CASCADE WHERE updater = $1 AND id <> $2;
