WITH latest AS (
	SELECT
		id
	FROM
		latest_update_operations
	WHERE
		updater = $1
		AND kind = 'enrichment'
	LIMIT 1
)
SELECT
	e.tags,
	e.data
FROM
	enrichment AS e,
	uo_enrich AS uo,
	latest
WHERE
	uo.uo = latest.id
	AND uo.enrich = e.id
	AND e.tags && $2::text[];
