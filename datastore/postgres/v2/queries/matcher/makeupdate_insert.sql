INSERT INTO vuln (hash_kind, hash, name, updater, description, issued, links, severity, normalized_severity, package_name, package_version, package_module, package_arch, package_kind, dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name, repo_name, repo_key, repo_uri, fixed_in_version, arch_operation, version_kind, vulnerable_range)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, VersionRange ($29, $30))
ON CONFLICT (hash_kind, hash)
	DO NOTHING;
