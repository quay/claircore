WITH layer AS (
	SELECT
		id
	FROM
		layer
	WHERE
		hash = $2
),
scanner AS (
	SELECT
		id
	FROM
		scanner
	WHERE
		scanner.name = $3
		AND scanner.version = $4
		AND scanner.kind = $5)
INSERT INTO dist_scanartifact (dist_id, layer_id, scanner_id)
SELECT
	dist.id AS dist_id,
	layer.id AS layer_id,
	scanner.id AS scanner_id
FROM
	UNNEST($1::int8[]) AS dist (id)
	CROSS JOIN layer
	CROSS JOIN scanner
ON CONFLICT
	DO NOTHING;