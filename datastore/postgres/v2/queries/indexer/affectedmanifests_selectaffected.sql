SELECT
	manifest.hash
FROM
	manifest_index
	JOIN manifest ON manifest_index.manifest_id = manifest.id
WHERE
	package_id = $1
	AND dist_id IS NOT DISTINCT FROM $2
	AND repo_id IS NOT DISTINCT FROM $3;
