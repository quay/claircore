WITH manifests AS (
    SELECT
        id AS manifest_id
    FROM
        manifest
    WHERE
        hash = $1)
INSERT INTO scanned_manifest (manifest_id, scanner_id)
    VALUES ((
            SELECT
                manifest_id
            FROM
                manifests),
            $2);

