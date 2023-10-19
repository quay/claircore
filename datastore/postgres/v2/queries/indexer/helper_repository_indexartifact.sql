WITH input AS (
	SELECT
		*
	FROM
		UNNEST($1::text[], $2::text[], $3::text[], $4::text[]) AS input (name,
			key,
			uri,
			cpe)
),
inserted AS (
INSERT INTO repo (name, key, uri, cpe)
	SELECT
		name,
		key,
		uri,
		cpe
	FROM
		input
	ON CONFLICT (name,
		key,
		uri)
		DO NOTHING
	RETURNING
		id
)
SELECT
	id
FROM
	inserted
UNION ALL
SELECT
	repo.id
FROM
	input
	JOIN repo USING (name, key, uri);
