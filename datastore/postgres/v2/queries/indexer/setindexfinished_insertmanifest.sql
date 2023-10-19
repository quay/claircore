INSERT INTO scanned_manifest (manifest_id, scanner_id)
SELECT
	manifest.id,
	scanner.id
FROM
	manifest
	CROSS JOIN (
		SELECT
			id
		FROM
			scanner
			JOIN UNNEST($2::text[], $3::text[], $4::text[]) AS input (name,
				version,
				kind)
			USING (name, version, kind)) AS scanner
WHERE
	hash = $1::text;
