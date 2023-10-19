INSERT INTO scanner (name, version, kind)
SELECT
	name,
	version,
	kind
FROM
	UNNEST($1::text[], $2::text[], $3::text[]) AS input (name,
		version,
		kind)
ON CONFLICT
	DO NOTHING;
