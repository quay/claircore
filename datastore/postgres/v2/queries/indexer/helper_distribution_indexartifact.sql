WITH input (
	name,
	did,
	version,
	version_code_name,
	version_id,
	arch,
	cpe,
	pretty_name
) AS (
	SELECT
		*
	FROM
		UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
),
inserted AS (
INSERT INTO dist (name, did, version, version_code_name, version_id, arch, cpe, pretty_name)
	SELECT
		name,
		did,
		version,
		version_code_name,
		version_id,
		arch,
		cpe,
		pretty_name
	FROM
		input
	ON CONFLICT (name,
		did,
		version,
		version_code_name,
		version_id,
		arch,
		cpe,
		pretty_name)
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
	dist.id
FROM
	input
	JOIN dist USING (name, did, version, version_code_name, version_id, arch, cpe, pretty_name);
