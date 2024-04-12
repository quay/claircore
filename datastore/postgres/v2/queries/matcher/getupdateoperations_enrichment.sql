SELECT
	ref,
	updater,
	fingerprint,
	date
FROM
	update_operation
WHERE
	updater = ANY ($1)
	AND kind = 'enrichment'
ORDER BY
	id DESC;
