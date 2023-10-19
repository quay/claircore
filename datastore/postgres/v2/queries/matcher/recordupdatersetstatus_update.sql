UPDATE
	updater_status
SET
	last_attempt = $1,
	last_success = $1,
	last_run_succeeded = 'true'
WHERE
	updater_name LIKE $2 || '%';
