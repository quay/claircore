WITH lhs AS (
	SELECT
		id,
		updater
	FROM
		update_operation
	WHERE
		ref = $1
),
rhs AS (
	SELECT
		id,
		updater
	FROM
		update_operation
	WHERE
		ref = $2
)
SELECT
	id,
	name,
	updater,
	description,
	issued,
	links,
	severity,
	normalized_severity,
	package_name,
	package_version,
	package_module,
	package_arch,
	package_kind,
	dist_id,
	dist_name,
	dist_version,
	dist_version_code_name,
	dist_version_id,
	dist_arch,
	dist_cpe,
	dist_pretty_name,
	arch_operation,
	repo_name,
	repo_key,
	repo_uri,
	fixed_in_version
FROM
	vuln
WHERE
	vuln.id IN (
		SELECT
			vuln AS id
		FROM
			uo_vuln
			JOIN lhs ON (uo_vuln.uo = lhs.id)
	EXCEPT ALL
	SELECT
		vuln AS id
	FROM
		uo_vuln
		JOIN rhs ON (uo_vuln.uo = rhs.id))
	AND (vuln.updater = (
			SELECT
				updater
			FROM
				rhs)
			OR vuln.updater = (
				SELECT
					updater
				FROM
					lhs));
