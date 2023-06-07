-- Delete all update_operations for osv updater and vulns
DELETE FROM update_operation WHERE updater = 'osv';

DELETE FROM vuln v1 USING
	vuln v2
	LEFT JOIN uo_vuln uvl
		ON v2.id = uvl.vuln
	WHERE uvl.vuln IS NULL
	AND v2.updater = 'osv'
AND v1.id = v2.id;
