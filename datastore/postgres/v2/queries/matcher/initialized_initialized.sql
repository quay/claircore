SELECT
	EXISTS (
		SELECT
			1
		FROM
			vuln
		LIMIT 1);
