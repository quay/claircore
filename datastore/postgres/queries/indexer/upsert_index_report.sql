WITH manifests AS (
    SELECT
        id AS manifest_id
    FROM
        manifest
    WHERE
        hash = $1
)
INSERT INTO
    indexreport (manifest_id, scan_result)
VALUES
    (
        (
            SELECT
                manifest_id
            FROM
                manifests
        ),
        $2
    ) ON CONFLICT (manifest_id) DO
UPDATE
SET
    scan_result = excluded.scan_result;
