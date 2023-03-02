SELECT
    scanner_id
FROM
    scanned_manifest
    JOIN manifest ON scanned_manifest.manifest_id = manifest.id
WHERE
    manifest.hash = $1;
