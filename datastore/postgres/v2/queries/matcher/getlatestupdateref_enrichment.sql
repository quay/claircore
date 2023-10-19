SELECT
	ref
FROM
	update_operation
WHERE
	kind = 'enrichment'
ORDER BY
	id USING >
LIMIT 1;
