SELECT
    id,
    name,
    version,
    kind,
    norm_kind,
    norm_version,
    module,
    arch
FROM
    package
WHERE
    name = $1;

