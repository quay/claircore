package migrations

const migration5 = `
	-- Helper view useful if you need to know how many vulnerabilities
	-- have been created by past update operations.
	CREATE OR REPLACE VIEW vulns_per_uo AS
		SELECT 	update_operation.ref,
				update_operation.updater,
				count(vuln.id) AS vuln_count
		FROM vuln
		JOIN uo_vuln ON vuln.id = uo_vuln.vuln
		JOIN update_operation ON uo_vuln.uo = update_operation.id
		GROUP BY update_operation.id
		ORDER BY vuln_count DESC;

	-- Helper view that exposes how many update operations have been
	-- created by distinct updaters. Useful for example when developing
	-- or debugging garbage collection.
	CREATE OR REPLACE VIEW uos_per_updater AS
		SELECT 	count(*) AS uo_count,
				update_operation.updater
		FROM update_operation
		GROUP BY update_operation.updater
		ORDER BY uo_count DESC;

	-- Helper view that lists all the vulnerabilities whose parent
	-- update operation has been deleted. Under normal circumstances,
	-- vulnerabilities like that should not exist.
	CREATE OR REPLACE VIEW orphaned_vulns AS
		SELECT 	count(*) AS vuln_count,
				vuln.updater
		FROM vuln
		LEFT JOIN uo_vuln ON vuln.id = uo_vuln.vuln
		WHERE uo_vuln.vuln IS NULL
		GROUP BY vuln.updater
`
