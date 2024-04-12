INSERT INTO indexreport (manifest_id, scan_result) 
SELECT
	manifest.id,
	$2::jsonb
FROM
	manifest
WHERE
	hash = $1::text
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET scan_result = excluded.scan_result;
