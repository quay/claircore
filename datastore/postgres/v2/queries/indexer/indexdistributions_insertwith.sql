WITH distributions AS (
	SELECT
		id AS dist_id
	FROM
		dist
	WHERE
		name = $1
		AND did = $2
		AND version = $3
		AND version_code_name = $4
		AND version_id = $5
		AND arch = $6
		AND cpe = $7
		AND pretty_name = $8
),
scanner AS (
	SELECT
		id AS scanner_id
	FROM
		scanner
	WHERE
		name = $9
		AND version = $10
		AND kind = $11
),
layer AS (
	SELECT
		id AS layer_id
	FROM
		layer
	WHERE
		layer.hash = $12)
INSERT INTO dist_scanartifact (layer_id, dist_id, scanner_id)
	VALUES ((
			SELECT
				layer_id
			FROM
				layer),
			(
				SELECT
					dist_id
				FROM
					distributions),
				(
					SELECT
						scanner_id
					FROM
						scanner))
		ON CONFLICT
			DO NOTHING;
