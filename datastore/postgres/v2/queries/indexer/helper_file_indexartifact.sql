WITH input (
	path,
	kind
) AS (
	SELECT * FROM
		UNNEST($1::text[], $2::text[])
),
inserted AS (
INSERT INTO file (path, kind)
	SELECT
		input.path,
		input.kind
	FROM
		input
	ON CONFLICT (path,
		kind)
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
	file.id
FROM
	input
	JOIN file USING (path, kind);
