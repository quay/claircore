INSERT INTO updater_status (updater_name, last_attempt, last_success, last_run_succeeded, last_attempt_fingerprint)
	VALUES ($1, $2, $2, 'true', $3)
ON CONFLICT (updater_name)
	DO UPDATE SET
		last_attempt = $2, last_success = $2, last_run_succeeded = 'true', last_attempt_fingerprint = $3
	RETURNING
		updater_name;
