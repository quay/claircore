WITH scanner AS MATERIALIZED (
	SELECT
		id
	FROM
		scanner
		JOIN UNNEST(
			$2::text[], $3::text[], $4::text[]
) AS find (
			name,
			version,
			kind
) USING (
			name, version, kind
))
SELECT
	ROW (file.path,
		file.kind)
FROM
	file_scanartifact
	JOIN file ON file_scanartifact.file_id = file.id
	JOIN scanner ON file_scanartifact.scanner_id = scanner.id
	JOIN layer ON file_scanartifact.layer_id = layer.id
WHERE
	layer.hash = $1::text;
