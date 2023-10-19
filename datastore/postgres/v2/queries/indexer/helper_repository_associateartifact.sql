WITH layer AS (
	SELECT
		id
	FROM
		layer
	WHERE
		hash = $2::text
),
scanner AS (
	SELECT
		id
	FROM
		scanner
	WHERE
		scanner.name = $3::text
		AND scanner.version = $4::text
		AND scanner.kind = $5::text)
INSERT INTO repo_scanartifact (repo_id, layer_id, scanner_id)
SELECT
	repo.id,
	layer.id,
	scanner.id
FROM
	UNNEST($1::int8[]) AS repo (id)
	CROSS JOIN layer
	CROSS JOIN scanner
ON CONFLICT
	DO NOTHING;
