SELECT
    package.id,
    package.name,
    package.kind,
    package.version,
    package.norm_kind,
    package.norm_version,
    package.module,
    package.arch,
    source_package.id,
    source_package.name,
    source_package.kind,
    source_package.version,
    source_package.module,
    source_package.arch,
    package_scanartifact.package_db,
    package_scanartifact.repository_hint
FROM
    package_scanartifact
    LEFT JOIN package ON package_scanartifact.package_id = package.id
    LEFT JOIN package AS source_package ON package_scanartifact.source_id = source_package.id
    JOIN layer ON layer.hash = $1
WHERE
    package_scanartifact.layer_id = layer.id
    AND package_scanartifact.scanner_id = ANY ($2);

