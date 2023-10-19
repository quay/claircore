SELECT DISTINCT ON (updater)
	updater,
	ref,
	fingerprint,
	date
FROM
	update_operation
ORDER BY
	updater,
	id USING >;
