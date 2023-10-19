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
	ROW (dist.id::text,
		dist.name,
		dist.did,
		dist.version,
		dist.version_code_name,
		dist.version_id,
		dist.arch,
		dist.cpe,
		dist.pretty_name)
FROM
	dist_scanartifact
	JOIN dist ON dist_scanartifact.dist_id = dist.id
	JOIN scanner ON dist_scanartifact.scanner_id = scanner.id
	JOIN layer ON dist_scanartifact.layer_id = layer.id
WHERE
	layer.hash = $1::text;
