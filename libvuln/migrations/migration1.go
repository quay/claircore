package migrations

const (
	migration1 = `
	-- Needed for uuid generation in-database.
	-- The inline function makes for a nicer error message.
	DO $$
	BEGIN
		EXECUTE 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"';
	EXCEPTION
		WHEN SQLSTATE '42501' THEN
			RAISE EXCEPTION 'Please load the "uuid-ossp" extension.'
			USING HINT = 'Role has insufficient permissions to CREATE EXTENSION';
		WHEN OTHERS THEN
			RAISE EXCEPTION 'Please load the "uuid-ossp" extension.';
	END;
	$$ LANGUAGE plpgsql;
	-- Update_operation is a table keeping a log of updater runs.
	--
	-- Ref is used when a specific update_operation needs to be exposed to a
	-- client.
	CREATE TABLE IF NOT EXISTS update_operation (
		id			BIGSERIAL PRIMARY KEY,
		ref         uuid UNIQUE DEFAULT uuid_generate_v4(),
		updater		TEXT NOT NULL,
		fingerprint TEXT,
		date		TIMESTAMP WITH TIME ZONE DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS uo_updater_idx ON update_operation (updater);
	-- Create the type used as a column later.
	CREATE TYPE VersionRange AS RANGE ( SUBTYPE = integer[10]);
	-- Vuln is a write-once table of vulnerabilities.
	--
	-- Updaters should attempt to insert vulnerabilities and on success or
	-- collision, insert a row into ou_vuln.
	CREATE TABLE IF NOT EXISTS vuln (
		id                     BIGSERIAL PRIMARY KEY,
		hash_kind              TEXT NOT NULL,
		hash                   BYTEA NOT NULL,
		updater                TEXT,
		name                   TEXT,
		description            TEXT,
		links                  TEXT,
		severity               TEXT,
		normalized_severity    TEXT,
		package_name           TEXT,
		package_version        TEXT,
		package_kind           TEXT,
		dist_id                TEXT,
		dist_name              TEXT,
		dist_version           TEXT,
		dist_version_code_name TEXT,
		dist_version_id        TEXT,
		dist_arch              TEXT,
		dist_cpe               TEXT,
		dist_pretty_name       TEXT,
		repo_name              TEXT,
		repo_key               TEXT,
		repo_uri               TEXT,
		fixed_in_version       TEXT,
		vulnerable_range       VersionRange NOT NULL DEFAULT VersionRange('{}', '{}', '()'),
		version_kind           TEXT,
		UNIQUE (hash_kind, hash)
	);
	-- These are some guesses at useful indexes. These should be measured.
	CREATE INDEX IF NOT EXISTS vuln_package_idx on vuln (
		package_name,
		package_kind,
		package_version
	);
	CREATE INDEX IF NOT EXISTS vuln_dist_idx on vuln (
		dist_id,
		dist_name,
		dist_version,
		dist_version_code_name,
		dist_version_id,
		dist_arch,
		dist_cpe,
		dist_pretty_name
	);
	CREATE INDEX IF NOT EXISTS vuln_repo_idx on vuln (
		repo_name,
		repo_key,
		repo_uri
	);
	-- Uo_vuln is the association table that does the many-many association
	-- between update operations and vulnerabilities.
	--
	-- The FKs enable us to GC the vulnerabilities by first removing old
	-- update_operation rows and having that cascade to this table, then
	-- remove vulnerabilities that are not referenced from this table.
	CREATE TABLE IF NOT EXISTS uo_vuln (
		uo   bigint REFERENCES update_operation (id) ON DELETE CASCADE,
		vuln bigint REFERENCES vuln             (id) ON DELETE CASCADE,
		PRIMARY KEY (uo, vuln)
	);
	-- Latest_vuln is a helper view to get the current snapshot of the vuln database.
	CREATE OR REPLACE VIEW latest_vuln AS
	SELECT v.*
	FROM (SELECT DISTINCT ON (updater) id FROM update_operation ORDER BY updater, id DESC) uo
		JOIN uo_vuln ON uo_vuln.uo = uo.id
		JOIN vuln v ON uo_vuln.vuln = v.id;`
)
