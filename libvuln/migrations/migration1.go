package migrations

const (
	migration1 = `
	CREATE TABLE IF NOT EXISTS update_operation
	(
		id			text PRIMARY KEY,
		updater		text,
		fingerprint text,
		date		timestamp with time zone
	);
	CREATE INDEX IF NOT EXISTS uo_updater_idx ON update_operation (updater);

	CREATE TABLE IF NOT EXISTS vuln
	(
		id                     BIGSERIAL PRIMARY KEY,
		uo_id                  text REFERENCES update_operation ON DELETE CASCADE,
		hash                   text,
		updater                text,
		name                   text,
		description            text,
		links                  text,
		severity               text,
		package_name           text,
		package_version        text,
		package_kind           text,
		dist_id                text,
		dist_name              text,
		dist_version           text,
		dist_version_code_name text,
		dist_version_id        text,
		dist_arch              text,
		dist_cpe               text,
		dist_pretty_name       text,
		repo_name              text,
		repo_key               text,
		repo_uri               text,
		fixed_in_version       text,
		active				   boolean
	);
	CREATE INDEX IF NOT EXISTS vuln_lookup_idx on vuln (active, package_name, dist_version_code_name, dist_pretty_name, dist_name,
														dist_version_id, dist_version, dist_arch, dist_cpe);
	CREATE UNIQUE INDEX IF NOT EXISTS unique_vulnerability_id ON vuln (uo_id, hash);
	`
)
