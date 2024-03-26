INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch)
SELECT
	input.name,
		input.kind,
		input.version,
		input.norm_kind,
		input.norm_version::int[],
		input.module,
		input.arch
FROM
	UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[]) AS input (name,
		kind,
		version,
		norm_kind,
		norm_version,
		module,
		arch)
ON CONFLICT (name,
	kind,
	version,
	module,
	arch)
	DO NOTHING;
