-- Delete all update_operations for pyupio to trigger pyupio vuln deletion
DELETE FROM update_operation
WHERE
  updater = 'pyupio';

DELETE FROM vuln v1 USING vuln v2
LEFT JOIN uo_vuln uvl ON v2.id = uvl.vuln
WHERE
  uvl.vuln IS NULL
  AND v2.updater = 'pyupio'
  AND v1.id = v2.id;
