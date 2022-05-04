SELECT
    scan_result
FROM
    indexreport
    JOIN manifest ON manifest.hash = $1
WHERE
    indexreport.manifest_id = manifest.id;

