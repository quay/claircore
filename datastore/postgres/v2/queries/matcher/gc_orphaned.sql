DELETE FROM vuln v1 USING vuln v2
	LEFT JOIN uo_vuln uvl ON v2.id = uvl.vuln
	WHERE uvl.vuln IS NULL
		AND v2.updater = $1
		AND v1.id = v2.id;
