INSERT
INTO
	update_operation (updater, fingerprint, kind)
VALUES
	($1, $2, 'enrichment')
RETURNING
	id, ref;
