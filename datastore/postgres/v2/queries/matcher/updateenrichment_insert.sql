INSERT
INTO
	enrichment (hash_kind, hash, updater, tags, data)
VALUES
	($1, $2, $3, $4, $5)
ON CONFLICT
	(hash_kind, hash)
DO
	NOTHING;
