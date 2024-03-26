SELECT
	package.id::text,
	package.name,
	package.kind,
	package.version,
	package.norm_kind,
	package.norm_version,
	package.module,
	package.arch,
	source_package.id,
	package_scanartifact.package_db,
	package_scanartifact.repository_hint,
	package_scanartifact.filepath
FROM
	package_scanartifact
	JOIN layer ON layer.id = package_scanartifact.layer_id
	LEFT JOIN package ON package_scanartifact.package_id = package.id
	LEFT JOIN package AS source_package ON package_scanartifact.source_id = source_package.id
	JOIN (
		SELECT
			id
		FROM
			scanner
			JOIN UNNEST($2::text[], $3::text[], $4::text[]) AS input (name,
				version,
				kind)
			USING (name, version, kind)) AS scanner ON scanner.id = package_scanartifact.scanner_id
WHERE
	layer.hash = $1;
