SELECT
    manifest.hash
FROM
    manifest_index
    JOIN manifest ON manifest_index.manifest_id = manifest.id
WHERE
    package_id = $1
    AND (
        CASE
            WHEN $2 :: INT8 IS NULL THEN dist_id IS NULL
            ELSE dist_id = $2
        END
    )
    AND (
        CASE
            WHEN $3 :: INT8 IS NULL THEN repo_id IS NULL
            ELSE repo_id = $3
        END
    );
