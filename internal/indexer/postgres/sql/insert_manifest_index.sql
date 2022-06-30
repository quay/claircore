WITH manifests AS (
    SELECT
        id AS manifest_id
    FROM
        manifest
    WHERE
        hash = $4)
INSERT INTO manifest_index (package_id, dist_id, repo_id, manifest_id)
    VALUES ($1, $2, $3, (
            SELECT
                manifest_id
            FROM
                manifests))
ON CONFLICT
    DO NOTHING;

