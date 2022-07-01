-- Needed for uuid generation in-database.
-- The inline function makes for a nicer error message.
DO $$
DECLARE
	hint text;
	detail text;
	code text;
BEGIN
	EXECUTE 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"';
EXCEPTION WHEN OTHERS THEN
	-- https://www.postgresql.org/docs/current/plpgsql-control-structures.html#PLPGSQL-EXCEPTION-DIAGNOSTICS
	GET STACKED DIAGNOSTICS
		code = RETURNED_SQLSTATE,
		detail = PG_EXCEPTION_DETAIL,
		hint = PG_EXCEPTION_HINT;
	RAISE EXCEPTION USING
		MESSAGE = 'Please load the "uuid-ossp" extension.',
		ERRCODE = code,
		DETAIL = detail,
		HINT = hint;
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
	issued                 timestamptz,
	links                  TEXT,
	severity               TEXT,
	normalized_severity    TEXT,
	package_name           TEXT,
	package_version        TEXT,
	package_module         TEXT,
	package_arch           TEXT,
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
	arch_operation         TEXT,
	vulnerable_range       VersionRange NOT NULL DEFAULT VersionRange('{}', '{}', '()'),
	version_kind           TEXT,
	UNIQUE (hash_kind, hash)
);
-- this index is tuned for the application. if you change this measure pre and post
-- change query speeds when generating vulnerability reports.
CREATE INDEX vuln_lookup_idx on vuln (package_name, dist_id,
                                         dist_name, dist_pretty_name,
                                         dist_version, dist_version_id,
                                         package_module, dist_version_code_name,
                                         repo_name, dist_arch,
                                         dist_cpe, repo_key,
                                         repo_uri);
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
	JOIN vuln v ON uo_vuln.vuln = v.id;
