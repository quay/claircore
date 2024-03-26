SELECT DISTINCT ON (updater)
	updater,
	ref,
	fingerprint,
	date
FROM
	update_operation
WHERE
	kind = 'enrichment'
ORDER BY
	updater,
	id USING >;
