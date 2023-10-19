INSERT INTO manifest_layer (manifest_id, layer_id, i)
SELECT
	m.id,
	l.id,
	l.n
FROM (
	SELECT
		id
	FROM
		manifest
	WHERE
		hash = $1::text) AS m,
	(
		SELECT
			id,
			n
		FROM
			layer
			JOIN UNNEST($2::text[])
			WITH ORDINALITY AS ls (hash, n) ON layer.hash = ls.hash) AS l
ON CONFLICT
	DO NOTHING;
