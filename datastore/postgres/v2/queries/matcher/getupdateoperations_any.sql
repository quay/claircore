SELECT
	ref,
	updater,
	fingerprint,
	date
FROM
	update_operation
WHERE
	updater = ANY ($1)
ORDER BY
	id DESC;
