package migrations

const (
	migration1 = `
CREATE TYPE VersionRange AS RANGE (
	SUBTYPE = integer[10]
);
--- a unique vulnerability indexed by an updater
CREATE TABLE vuln (
    updater text,
    --- claircore.Vulnerability fields
    id BIGSERIAL PRIMARY KEY,
    name text,
    description text,
    links text,
    severity text,
    normalized_severity text,
    package_name text,
    package_version text,
    package_kind text,
    dist_id text,
    dist_name text,
    dist_version text,
    dist_version_code_name text,
    dist_version_id text,
    dist_arch text,
    dist_cpe text,
    dist_pretty_name text,
    repo_name text,
    repo_key text,
    repo_uri text,
    fixed_in_version text,
	-- Provide a default range that contains nothing, because a NULL seems to
	-- contain everything.
	vulnerable_range VersionRange NOT NULL DEFAULT VersionRange('{}', '{}', '()'),
	-- Note the kind of the versions in the range.
	-- It's the application's responsibility to make sure they agree.
	version_kind text,
    --- a tombstone field that will be updated to signify a vulnerability is not stale
    tombstone text
);
CREATE INDEX vuln_lookup_idx on vuln(package_name, dist_version_code_name, dist_pretty_name, dist_name, dist_version_id, dist_version, dist_arch, dist_cpe);
CREATE UNIQUE INDEX vuln_unique_idx on vuln(  
        updater, 
        name, 
        md5(description), 
        links,
        severity,
        normalized_severity,
        package_name, 
        package_version, 
        package_kind, 
        dist_id, 
        dist_name, 
        dist_version, 
        dist_version_code_name, 
        dist_version_id, 
        dist_arch,
        dist_cpe,
        dist_pretty_name,
        repo_name,
        repo_key,
        repo_uri,
        fixed_in_version
    );

--- UpdateHash
--- a key/value hstore holding the latest update hash for a particular updater
CREATE TABLE updatecursor (
    --- the unique name of the updater. acts a primary key. a single cursor is kept for a particular class
    --- of updater
    updater text PRIMARY KEY,
    --- the last seen hash of the vulnerability database the updater is reponsible for
    hash text,
    --- the last tombstone each vulnerability was created or updated with
    tombstone text
);
`
)
