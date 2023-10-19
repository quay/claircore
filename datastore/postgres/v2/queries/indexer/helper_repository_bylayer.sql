SELECT
	ROW (repo.id::text,
		repo.name,
		repo.key,
		repo.uri,
		repo.cpe)
FROM
	repo_scanartifact
	LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
	JOIN layer ON layer.hash = $1::text
WHERE
	repo_scanartifact.layer_id = layer.id
	AND repo_scanartifact.scanner_id = ANY (
		SELECT
			id
		FROM
			scanner
			JOIN UNNEST($2::text[], $3::text[], $4::text[]) AS input (name,
				version,
				kind)
			USING (name, version, kind));
