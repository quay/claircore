INSERT INTO package_scanartifact (layer_id, package_db, repository_hint, filepath, package_id, source_id, scanner_id)
SELECT
	layer.id,
	input.package_db,
	input.repository_hint,
	input.filepath,
	package.id,
	source.id,
	scanner.id
FROM
	UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $15::text[], $16::text[], $17::text[]) AS input (src_name,
		src_kind,
		src_version,
		src_module,
		src_arch,
		bin_name,
		bin_kind,
		bin_version,
		bin_module,
		bin_arch,
		package_db,
		repository_hint,
		filepath)
	JOIN layer ON layer.hash = $14::text
	JOIN package ON package.name = input.bin_name
		AND package.kind = input.bin_kind
		AND package.version = input.bin_version
		AND package.module = input.bin_module
		AND package.arch = input.bin_arch
	JOIN package AS source ON source.name = input.src_name
		AND source.kind = input.src_kind
		AND source.version = input.src_version
		AND source.module = input.src_module
		AND source.arch = input.src_arch
	JOIN scanner ON scanner.name = $11
		AND scanner.version = $12
		AND scanner.kind = $13
	ON CONFLICT
		DO NOTHING;
