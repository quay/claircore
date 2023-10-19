SELECT
	bool_and(q.ok)
FROM (
	SELECT
		scanner.id IS NOT NULL AS ok
	FROM
		scanned_manifest
		JOIN manifest ON scanned_manifest.manifest_id = manifest.id
		LEFT OUTER JOIN (
			SELECT
				id
			FROM
				scanner
				JOIN UNNEST($2::text[], $3::text[], $4::text[]) AS input (name,
					version,
					kind)
				USING (name, version, kind)) AS scanner ON scanned_manifest.scanner_id = scanner.id
		WHERE
			manifest.hash = $1) AS q;
