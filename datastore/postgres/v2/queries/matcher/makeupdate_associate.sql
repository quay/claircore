INSERT INTO uo_vuln (uo, vuln)
	VALUES ($3, (
			SELECT
				id
			FROM
				vuln
			WHERE
				hash_kind = $1
				AND hash = $2))
ON CONFLICT
	DO NOTHING;
