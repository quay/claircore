SELECT
    repo.id,
    repo.name,
    repo.key,
    repo.uri,
    repo.cpe
FROM
    repo_scanartifact
    LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
    JOIN layer ON layer.hash = $1
WHERE
    repo_scanartifact.layer_id = layer.id
    AND repo_scanartifact.scanner_id = ANY ($2);

