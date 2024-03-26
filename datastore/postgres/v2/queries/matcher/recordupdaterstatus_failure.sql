INSERT INTO updater_status (updater_name, last_attempt, last_run_succeeded, last_attempt_fingerprint, last_error)
	VALUES ($1, $2, 'false', $3, $4)
ON CONFLICT (updater_name)
	DO UPDATE SET
		last_attempt = $2, last_run_succeeded = 'false', last_attempt_fingerprint = $3, last_error = $4
	RETURNING
		updater_name;
