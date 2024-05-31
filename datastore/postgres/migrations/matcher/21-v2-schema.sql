-- vim: set foldmethod=marker :
-- It's dangerous to go alone! Take this.
-- https://www.postgresql.org/docs/current/plpgsql.html
CREATE SCHEMA matcher_v2;

COMMENT ON SCHEMA matcher_v2 IS $$
Matcher_v2 is a revised version of the schema for storing data to match against.

Compared with the v1 structure this version normalizes more data, avoids some excessive write traffic pitfalls, and avoids client-side hashing schemes.
$$;

SET
  LOCAL search_path TO matcher_v2,
  "$user",
  public;

-- {{{ Domain types
CREATE TYPE Severity AS ENUM(
  'Unknown',
  'Negligible',
  'Low',
  'Medium',
  'High',
  'Critical'
);

COMMENT ON TYPE Severity IS 'Severity values are the defined Claircore "normalized" values.';

-- {{{ VersionRange
CREATE TYPE VersionRange AS RANGE (
  SUBTYPE = TEXT[]
  -- It would be great to be able to have a "canonical" function here that
  -- handled digit-only strings transparently, but it's impossible:
  -- 1. A shell type is a base type, so the user must be a superuser
  -- 2. A PL cannot interact with shell types, so the function must be written in C.
);

COMMENT ON TYPE VersionRange IS 'VersionRange is a type for doing version comparisons in a standard way.';

CREATE OR REPLACE FUNCTION version_check_array (vs TEXT[]) RETURNS BOOLEAN IMMUTABLE STRICT PARALLEL SAFE LANGUAGE plpgsql AS $$
DECLARE
	v TEXT;
BEGIN
	FOREACH v IN ARRAY vs LOOP
		IF v ~ '\s' OR (v ~ '^\d+$' AND length(v) <> 10) THEN
			RETURN FALSE;
		END IF;
	END LOOP;
	RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION version_check_array IS 'This function reports whether a text array is well-formed to be used as a VersionRange';

CREATE OR REPLACE FUNCTION version_check (mr matcher_v2.VersionMultiRange) RETURNS BOOLEAN IMMUTABLE STRICT PARALLEL SAFE LANGUAGE plpgsql AS $$
DECLARE
	v matcher_v2.VersionRange;
BEGIN
	FOR v IN
	SELECT
		unnest(mr)
		LOOP
			IF NOT matcher_v2.version_check_array (lower(v)) AND matcher_v2.version_check_array (upper(v)) THEN
				RETURN FALSE;
			END IF;
		END LOOP;
	RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION version_check IS 'This function reports whether VersionMultiRange has well-formed VersionRange members.';

-- }}}
CREATE TYPE PackageKind AS ENUM('source', 'binary');

COMMENT ON TYPE PackageKind IS 'Enum for package kinds.';

CREATE TYPE Architecture AS ENUM(
  'any',
  '386',
  'amd64',
  'arm',
  'arm64',
  'mips',
  'mipsle',
  'mips64',
  'mips64le',
  'ppc64',
  'ppc64le',
  'riscv64',
  's390x'
);

COMMENT ON TYPE Architecture IS 'Enum for architectures. The text value is in Go notation';

-- }}}
-- {{{ Updater table
CREATE TABLE updater (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "name" TEXT UNIQUE NOT NULL
);

COMMENT ON TABLE updater IS 'Updater keeps track of known Updaters in the system.';

COMMENT ON COLUMN updater.name IS 'Updater name.';

CREATE OR REPLACE FUNCTION updater_id (n TEXT) RETURNS BIGINT STRICT LANGUAGE plpgsql AS $$
DECLARE
	out BIGINT;
BEGIN
	SELECT id INTO out FROM matcher_v2.updater WHERE name = n;
	IF NOT FOUND THEN
		INSERT INTO matcher_v2.updater (name)
			VALUES (n)
		RETURNING
			id INTO out;
	END IF;
	RETURN out;
END;
$$;

COMMENT ON FUNCTION updater_id IS 'Updater_id returns the id of the named updater, creating it if needed.';

-- }}}
-- {{{ Run tables
CREATE TABLE run (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ref UUID UNIQUE NOT NULL,
  date TIMESTAMP WITH TIME ZONE DEFAULT now(),
  complete BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE run IS 'Run logs updater system runs.';

COMMENT ON COLUMN run.ref IS 'UUID for client presentation. Prevents leaking database IDs.';

COMMENT ON COLUMN run.date IS 'Timestamp of this run. For debugging and reporting.';

COMMENT ON COLUMN run.complete IS 'Has this run completed? Allows a run to be created outside a transaction.';

CREATE TABLE updater_run (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ref UUID UNIQUE NOT NULL,
  updater BIGINT NOT NULL REFERENCES updater (id) ON DELETE CASCADE,
  run BIGINT NOT NULL REFERENCES run (id) ON DELETE CASCADE,
  success BOOLEAN GENERATED ALWAYS AS (error IS NULL) STORED,
  fingerprint JSONB,
  error TEXT
);

CREATE INDEX updater_run_updater_fk_idx ON updater_run (updater);

CREATE INDEX updater_run_run_fk_idx ON updater_run (run);

COMMENT ON TABLE updater_run IS 'Updater_run logs specific updater runs.';

COMMENT ON COLUMN updater_run.ref IS 'UUID for client presentation. Prevents leaking database IDs.';

COMMENT ON COLUMN updater_run.updater IS 'Reference to updater(id).';

COMMENT ON COLUMN updater_run.run IS 'Reference to run(id).';

COMMENT ON COLUMN updater_run.success IS 'Whether an error was reported for this run.';

COMMENT ON COLUMN updater_run.fingerprint IS 'Fingerprint is JSON metadata passed into the next Updater run.';

COMMENT ON COLUMN updater_run.error IS 'Error reported from the run. For debugging and reporting; may be NULL.';

COMMENT ON INDEX updater_run_updater_fk_idx IS 'Index on foreign key for less costly deletes and joins.';

COMMENT ON INDEX updater_run_run_fk_idx IS 'Index on foreign key for less costly deletes and joins.';

-- }}}
-- {{{ GC
CREATE OR REPLACE PROCEDURE run_gc () LANGUAGE plpgsql AS $$
DECLARE
	config JSONB;
	rm_ref UUID;
	rm_date TIMESTAMP WITH TIME ZONE;
	rm_name TEXT;
	rm_names TEXT[];
	count INTEGER;
	-- Config values:
	retain_runs INTEGER;
BEGIN
	config := matcher_v2_meta.latest_config ();
	SELECT
		INTO retain_runs coalesce((config -> 'retain_runs')::INTEGER, 1);

	CALL matcher_v2_meta.emit_log ('gc', 'start');

	FOR rm_ref, rm_date IN
		DELETE FROM matcher_v2.run
		WHERE id <= (
				SELECT
					id
				FROM
					matcher_v2.run
				ORDER BY
					id DESC
				LIMIT 1 OFFSET retain_runs)
		RETURNING
			ref, date
	LOOP
		CALL matcher_v2_meta.emit_log ('gc', 'deleted run', jsonb_build_object('ref', rm_ref, 'date', rm_date));
	END LOOP;

	FOR rm_name IN
		DELETE FROM matcher_v2.updater
		WHERE NOT EXISTS (
				SELECT
					1
				FROM
					matcher_v2.updater_run
				WHERE
					updater = updater.id)
		RETURNING
			"name"
	LOOP
		CALL matcher_v2_meta.emit_log ('gc', 'deleted updater', jsonb_build_object('name', rm_name));
	END LOOP;

	INSERT INTO matcher_v2_meta.log(kind, event, message)
	SELECT
		'gc',
		jsonb_build_object('updaters', array_agg(updater.name)),
		'updaters in use'
	FROM
		matcher_v2.updater;

	WITH del (name) AS (
	DELETE FROM matcher_v2.reference WHERE NOT EXISTS (
		SELECT 1 FROM matcher_v2.advisory_reference WHERE reference = reference.id
	) RETURNING namespace || '-' || "name"
	)
	SELECT COALESCE(array_agg(del.name), ARRAY[]::TEXT[]) INTO rm_names FROM del;
	CALL matcher_v2_meta.emit_log ('gc', 'deleted references', jsonb_build_object('names', rm_names));

	WITH del (name) AS (
	DELETE FROM matcher_v2.package_name WHERE NOT EXISTS (
		SELECT 1 FROM matcher_v2.package WHERE name = package_name.id
	) RETURNING name
	)
	SELECT COALESCE(array_agg(del.name), ARRAY[]::TEXT[]) INTO rm_names FROM del;
	CALL matcher_v2_meta.emit_log ('gc', 'deleted package names', jsonb_build_object('names', rm_names));

	DELETE FROM matcher_v2.attr WHERE NOT EXISTS (
		SELECT 1 FROM matcher_v2.advisory_attr WHERE attr = attr.id
	);
	GET DIAGNOSTICS count = ROW_COUNT;
	CALL matcher_v2_meta.emit_log ('gc', 'deleted attrs', jsonb_build_object('count', count));

	WITH del (name) AS (
	DELETE FROM matcher_v2.mediatype WHERE NOT EXISTS (
		SELECT 1 FROM matcher_v2.attr WHERE mediatype = mediatype.id
	) RETURNING mediatype
	)
	SELECT COALESCE(array_agg(del.name), ARRAY[]::TEXT[]) INTO rm_names FROM del;
	CALL matcher_v2_meta.emit_log ('gc', 'deleted media types', jsonb_build_object('mediatypes', rm_names));

	CALL matcher_v2_meta.emit_log ('gc', 'done');
END;
$$;

COMMENT ON PROCEDURE run_gc () IS $$
Run_gc runs a garbage collection pass.

Uses the config keys:
- retain_runs
  Number of runs to retain per updater. (default: 1, meaning no history)
$$;

CREATE OR REPLACE PROCEDURE run_vacuum () LANGUAGE SQL AS $$
	VACUUM (ANALYZE, PARALLEL 2)
		matcher_v2.advisory,
		matcher_v2.advisory_meta,
		matcher_v2.reference,
		matcher_v2.advisory_reference,
		matcher_v2.package,
		matcher_v2.package_name,
		matcher_v2.mediatype,
		matcher_v2.attr,
		matcher_v2.advisory_attr;
$$;

COMMENT ON PROCEDURE run_vacuum () IS 'Helper for vacuumining the correct tables after GC.';

-- }}}
-- {{{ Advisory table
CREATE TABLE advisory (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  added BIGINT REFERENCES run (id) ON DELETE SET NULL, -- NB can be NULL
  generation BIGINT NOT NULL REFERENCES run (id) ON DELETE CASCADE,
  updater BIGINT NOT NULL REFERENCES updater (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  UNIQUE (updater, name)
);

CREATE INDEX advisory_added_fk_idx ON advisory (added);

CREATE INDEX advisory_generation_fk_idx ON advisory (generation);

COMMENT ON TABLE advisory IS 'Advisory is the parent object for an advisory.';

COMMENT ON COLUMN advisory.added IS 'Reference to run(id). Used for garbage collection.';

COMMENT ON COLUMN advisory.generation IS 'Reference to run(id). Used for garbage collection.';

COMMENT ON COLUMN advisory.updater IS 'Reference to updater(id). Used to namespace the advisory name.';

COMMENT ON COLUMN advisory.name IS 'Stable ID for the advisory within the updater''s namespace.';

COMMENT ON INDEX advisory_added_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

COMMENT ON INDEX advisory_generation_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

CREATE OR REPLACE FUNCTION advisory_id (gen BIGINT, upd BIGINT, n TEXT) RETURNS BIGINT STRICT LANGUAGE plpgsql AS $$
DECLARE
	out BIGINT;
BEGIN
	INSERT INTO matcher_v2.advisory (updater, name, generation, added)
		VALUES (upd, n, gen, gen)
	ON CONFLICT (updater, name)
		DO UPDATE SET
			generation = gen
		RETURNING
			id INTO out;
	RETURN out;
END;
$$;

COMMENT ON FUNCTION advisory_id IS 'Return the ID for the provided (updater, name) pair. Updates the observed generation.';

CREATE OR REPLACE VIEW latest_advisory AS
SELECT
  advisory.*
FROM
  matcher_v2.advisory
  JOIN (
    SELECT
      id
    FROM
      matcher_v2.run
    ORDER BY
      id DESC
    LIMIT
      1
  ) run ON run.id = advisory.generation;

COMMENT ON VIEW latest_advisory IS 'Latest_advisory is a view to simplify looking at the latest set of advisories.';

CREATE TABLE advisory_meta (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  advisory BIGINT NOT NULL UNIQUE REFERENCES advisory (id) ON DELETE CASCADE,
  issued TIMESTAMPTZ,
  summary TEXT,
  description TEXT,
  uri TEXT,
  severity TEXT,
  normalized_severity Severity
);

CREATE INDEX advisory_meta_advisory_fk_idx ON advisory_meta (advisory);

COMMENT ON TABLE advisory_meta IS $$
Advisory_meta is metadata not needed for matching or updating.

Try to avoid indexes on this table so it's stored as HOT (https://www.postgresql.org/docs/current/storage-hot.html).
$$;

COMMENT ON COLUMN advisory_meta.advisory IS 'Foreign key to the advisory';

COMMENT ON COLUMN advisory_meta.issued IS 'When the advisory was issued';

COMMENT ON COLUMN advisory_meta.summary IS 'Human-readable summary from the advisory.';

COMMENT ON COLUMN advisory_meta.description IS 'Human-readable description from the advisory. Likely much longer than the summary.';

COMMENT ON COLUMN advisory_meta.uri IS 'Canonical URL for the advisory. Additional URLs may be in the "reference" table.';

COMMENT ON COLUMN advisory_meta.severity IS 'Literal severity as reported in the advisory.';

COMMENT ON COLUMN advisory_meta.normalized_severity IS 'Reported severity normalized to the Clair scale.';

COMMENT ON INDEX advisory_meta_advisory_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

-- }}}
-- {{{ Reference table
CREATE TABLE reference (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  uri TEXT[],
  UNIQUE (namespace, "name")
);

CREATE INDEX reference_namespace_name_idx ON reference (namespace, name);

COMMENT ON TABLE reference IS 'References are names shared across databases.';

COMMENT ON COLUMN reference.namespace IS 'Reference namespace, eg "CVE" or "RHSA".';

COMMENT ON COLUMN reference.name IS 'References'' namespaced name, eg "2014-0160" or "2014-0376".';

COMMENT ON COLUMN reference.uri IS 'An array of URIs for more information.';

COMMENT ON INDEX reference_namespace_name_idx IS 'Index on namespace-name pair to help reverse-lookups.';

CREATE OR REPLACE FUNCTION reference_id (ns TEXT, n TEXT) RETURNS BIGINT STRICT LANGUAGE plpgsql AS $$
DECLARE
	out BIGINT;
BEGIN
	INSERT INTO matcher_v2.reference (namespace, name)
		VALUES (ns, n)
	ON CONFLICT (namespace, name)
		DO NOTHING
	RETURNING
		id INTO out;
	RETURN out;
END;
$$;

COMMENT ON FUNCTION reference_id IS 'Return the ID for the provided (namespace, name) pair.';

CREATE TABLE advisory_reference (
  advisory BIGINT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
  reference BIGINT NOT NULL REFERENCES reference (id) ON DELETE CASCADE,
  PRIMARY KEY (advisory, reference)
);

CREATE INDEX advisory_reference_reference_fk_idx ON advisory_reference (reference);

COMMENT ON TABLE advisory_reference IS 'Advisory_reference is the many-many mapping between advisories and references.';

COMMENT ON COLUMN advisory_reference.advisory IS 'Foreign key to the advisory table.';

COMMENT ON COLUMN advisory_reference.reference IS 'Foreign key to the reference table.';

COMMENT ON INDEX advisory_reference_reference_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

-- }}}
-- {{{ Package table
CREATE TABLE package_name (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

COMMENT ON TABLE package_name IS 'Package_name is the table for interning package names.';

COMMENT ON COLUMN package_name.name IS 'Package name.';

CREATE OR REPLACE FUNCTION package_name_id (n TEXT) RETURNS BIGINT STRICT LANGUAGE plpgsql AS $$
DECLARE
	out BIGINT;
BEGIN
	INSERT INTO matcher_v2.package_name (name)
		VALUES (n)
	ON CONFLICT (name)
		DO NOTHING
	RETURNING
		id INTO out;
	RETURN out;
END;
$$;

COMMENT ON FUNCTION package_name_id IS 'Return the ID for the provided name.';

CREATE TABLE package (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  advisory BIGINT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
  name BIGINT NOT NULL REFERENCES package_name (id),
  kind PackageKind,
  arch Architecture[],
  vulnerable_range VersionMultiRange NOT NULL CHECK (version_check (vulnerable_range)),
  version_upstream TEXT[],
  version_kind TEXT,
  purl TEXT,
  cpe TEXT,
  UNIQUE (advisory, name, kind)
);

CREATE INDEX package_advisory_fk_idx ON package (advisory);

CREATE INDEX package_package_name_fk_idx ON package (name);

COMMENT ON TABLE package IS 'Package is the table containing software packages referenced in advisories. Packages are a special case of Attr.';

COMMENT ON COLUMN package.advisory IS 'Foreign key to the advisory table.';

COMMENT ON COLUMN package.name IS 'Foreign key to the package_name table.';

COMMENT ON COLUMN package.kind IS 'The "kind" of this package.';

COMMENT ON COLUMN package.arch IS 'Array of applicable architectures.';

COMMENT ON COLUMN package.vulnerable_range IS 'The normalized version ranges of an affected package.';

COMMENT ON COLUMN package.version_upstream IS 'The literal version strings as reported in the advisory.';

COMMENT ON COLUMN package.version_kind IS 'The "kind" of the upstream version. Range operations are unlikely to make sense if this is not the expected kind.';

COMMENT ON COLUMN package.purl IS 'The purl of this package. Version information should be omitted, as this is not describing a single package.';

COMMENT ON COLUMN package.cpe IS 'The CPE for this package.';

COMMENT ON INDEX package_advisory_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

COMMENT ON INDEX package_package_name_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

-- }}}
-- {{{ Attr table
CREATE TABLE mediatype (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  mediatype TEXT UNIQUE NOT NULL
);

COMMENT ON TABLE mediatype IS 'Mediatype is the table for interning mediatypes.';

COMMENT ON COLUMN mediatype.mediatype IS 'Media type. Should have an "application" type, although this is not currently enforced.';

CREATE TABLE attr (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  mediatype BIGINT NOT NULL REFERENCES mediatype (id) ON DELETE CASCADE,
  data JSONB NOT NULL
);

CREATE INDEX attr_mediatype_fk_idx ON attr (mediatype);

CREATE INDEX attr_data_gidx ON attr USING GIN (data jsonb_path_ops);

CREATE INDEX attr_data_hidx ON attr USING HASH (data);

ALTER TABLE attr
ADD UNIQUE (mediatype, data);

COMMENT ON TABLE attr IS $$
Attrs are generic features of advisories and references.

The attrs on references replaces the previous matcher's "enrichments".
$$;

COMMENT ON COLUMN attr.mediatype IS 'Foreign key to the mediatype table.';

COMMENT ON COLUMN attr.data IS 'Data is key-value data.';

COMMENT ON INDEX attr_mediatype_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

COMMENT ON INDEX attr_data_gidx IS 'Index for jsonpath operations. Does not support key-exists operators.';

COMMENT ON INDEX attr_data_hidx IS 'Index for equality operator.';

CREATE TABLE advisory_attr (
  advisory BIGINT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
  attr BIGINT NOT NULL REFERENCES attr (id) ON DELETE CASCADE,
  PRIMARY KEY (advisory, attr)
);

CREATE INDEX advisory_attr_advisory_fk_idx ON advisory_attr (advisory);

CREATE INDEX advisory_attr_attr_fk_idx ON advisory_attr (attr);

COMMENT ON TABLE advisory_attr IS 'Advisory_attr is the many-to-many mapping of advisories and attrs.';

COMMENT ON COLUMN advisory_attr.advisory IS 'Foreign key to the advisory table.';

COMMENT ON COLUMN advisory_attr.attr IS 'Foreign key to the attr table.';

COMMENT ON INDEX advisory_attr_advisory_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

COMMENT ON INDEX advisory_attr_attr_fk_idx IS 'Index on foreign key for less costly deletes & joins.';

-- }}}
DO LANGUAGE plpgsql $$
BEGIN
	CALL matcher_v2_meta.emit_log ('init', 'matcher_v2 schema populated');
END
$$;
