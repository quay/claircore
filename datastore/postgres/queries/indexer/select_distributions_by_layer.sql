SELECT
    dist.id,
    dist.name,
    dist.did,
    dist.version,
    dist.version_code_name,
    dist.version_id,
    dist.arch,
    dist.cpe,
    dist.pretty_name
FROM
    dist_scanartifact
    LEFT JOIN dist ON dist_scanartifact.dist_id = dist.id
    JOIN layer ON layer.hash = $1
WHERE
    dist_scanartifact.layer_id = layer.id
    AND dist_scanartifact.scanner_id = ANY($2);
