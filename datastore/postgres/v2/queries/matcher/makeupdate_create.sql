INSERT INTO update_operation (updater, fingerprint, kind)
	VALUES ($1, $2, 'vulnerability')
RETURNING
	id, ref;
