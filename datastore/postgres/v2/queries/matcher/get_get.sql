SELECT
	vuln.id,
	name,
	description,
	issued,
	links,
	severity,
	normalized_severity,
	package_name,
	package_version,
	package_module,
	package_arch,
	package_kind,
	dist_id,
	dist_name,
	dist_version,
	dist_version_code_name,
	dist_version_id,
	dist_arch,
	dist_cpe,
	dist_pretty_name,
	arch_operation,
	repo_name,
	repo_key,
	repo_uri,
	fixed_in_version,
	vuln.updater,
	vulnerable_range,
	version_kind
FROM
	vuln
	INNER JOIN uo_vuln ON (vuln.id = uo_vuln.vuln)
	INNER JOIN latest_update_operations ON (latest_update_operations.id = uo_vuln.uo)
WHERE ((("package_name" = $1::text)
		AND ("package_kind" = 'binary'))
	OR ($2::text IS NOT NULL
		AND ("package_name" = $2::text)
		AND ("package_kind" = 'source')))
AND ($3::text IS NULL
	OR "package_module" = $3::text)
AND ($4::text IS NULL
	OR "dist_id" = $4::text)
AND ($5::text IS NULL
	OR "dist_name" = $5::text)
AND ($6::text IS NULL
	OR "dist_version_id" = $6::text)
AND ($7::text IS NULL
	OR "dist_version" = $7::text)
AND ($8::text IS NULL
	OR "dist_version_code_name" = $8::text)
AND ($9::text IS NULL
	OR "dist_pretty_name" = $9::text)
AND ($10::text IS NULL
	OR "dist_cpe" = $10::text)
AND ($11::text IS NULL
	OR "dist_arch" = $11::text)
AND ($12::text IS NULL
	OR "repo_name" = $12::text)
AND ($13::text IS NULL
	OR ("version_kind" = $13::text
		AND "vulnerable_range" @> $14::int[]))
AND ("latest_update_operations"."kind" = 'vulnerability');
