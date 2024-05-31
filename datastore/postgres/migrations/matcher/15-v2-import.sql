-- vim: set foldmethod=marker :
-- The formatting in this file is best-effort, all SQL formatters are garbage.
-- It's dangerous to go alone! Take this.
-- https://www.postgresql.org/docs/current/plpgsql.html

CREATE SCHEMA matcher_v2_import;

COMMENT ON SCHEMA matcher_v2_import IS $$
Matcher_v2_import holds all the machinery for importing advisories.

To use:
1. Create (in `matcher_v2`) rows for a `run`, `updater`, and `updater_run` and record the resulting IDs.
2. Call `stage` to prepare temporary tables.
3. Load the temporary table (`advisory_import`) with data
4. Call `commit_snapshot`, `commit_add`, or `commit_remove` as needed.
5. Repeat steps 3 and 4 as needed.
6. Call `finish` to update the tables in the `matcher_v2` schema with any pending changes.

The above is all assumed to be done in a transaction, but the procedures do not currently enforce this.
$$;

SET LOCAL search_path TO matcher_v2_import,"$user",public;
-- {{{ Shadow types
-- These are composite types shadowing the row types in the matcher_v2 schema.
-- Make sure to ALTER these when those tables are ALTERed.
CREATE TYPE advisory AS (
	name TEXT,
	issued TIMESTAMPTZ,
	summary TEXT,
	description TEXT,
	uri TEXT,
	severity TEXT,
	normalized_severity matcher_v2.Severity
);
COMMENT ON TYPE advisory IS 'Advisory information needed for import.';

CREATE TYPE reference AS (
	namespace TEXT,
	name TEXT,
	uri TEXT[]
);
COMMENT ON TYPE reference IS 'Reference information needed for import.';

CREATE TYPE package AS (
	name TEXT,
	kind matcher_v2.PackageKind,
	arch matcher_v2.Architecture[],
	vulnerable_range matcher_v2.VersionMultiRange,
	version_upstream TEXT[],
	version_kind TEXT,
	purl TEXT,
	cpe TEXT
);
COMMENT ON TYPE package IS 'Package information needed for import.';

CREATE TYPE attr AS (
	mediatype TEXT,
	data JSONB
);
COMMENT ON TYPE attr IS 'Attr information needed for import.';

CREATE TYPE advisory_import_row AS (
	-- id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	advisory_id BIGINT,
	advisory matcher_v2_import.advisory,
	reference matcher_v2_import.reference[],
	package matcher_v2_import.package[],
	attr matcher_v2_import.attr[]
);

COMMENT ON TYPE advisory_import_row IS 'Advisory_import_row is the shape of the "advisory_import" table. It is disallowed to SET the "id" column.';
-- }}}
CREATE FUNCTION array_distinct (a anyarray)
	RETURNS anyarray
	LANGUAGE SQL
	IMMUTABLE STRICT
	AS $$
	SELECT
		array_agg(DISTINCT x)
	FROM
		unnest(a) t (x);
$$;

COMMENT ON FUNCTION array_distinct IS 'Array_distinct returns an array with only distinct elements.';
-- {{{ Run management
CREATE OR REPLACE FUNCTION start_run (ref UUID)
	RETURNS BIGINT
	LANGUAGE plpgsql
	STRICT
	AS $$
BEGIN
	INSERT INTO matcher_v2.run (ref) VALUES(ref) RETURNING id;
END;
$$;

COMMENT ON FUNCTION start_run IS 'Create a `matcher_v2.run` object, returning the ID.';

CREATE OR REPLACE FUNCTION start_updater_run (ref UUID, upd BIGINT, run BIGINT)
	RETURNS BIGINT
	LANGUAGE plpgsql
	STRICT
	AS $$
BEGIN
	INSERT INTO matcher_v2.updater_run (ref, updater, run)
		VALUES (upd_run_ref, upd_id, run_id)
	RETURNING
		id;
END;
$$;

COMMENT ON FUNCTION start_updater_run IS $$Create a `matcher_v2.update_run` object, returning the ID.

See also: start_run, matcher_v2.updater_id
$$;

CREATE OR REPLACE FUNCTION finish_updater_run (id BIGINT, fingerprint JSONB, error TEXT)
	RETURNS void
	LANGUAGE plpgsql
	AS $$
BEGIN
	UPDATE
		matcher_v2.updater_run
	SET
		fingerprint = fingerprint,
		error = error
	WHERE
		id = id;
END;
$$;

COMMENT ON FUNCTION finish_updater_run IS 'Finish_updater_run should be called when an updater''s import is completed.';

CREATE OR REPLACE FUNCTION finish_run (id BIGINT)
	RETURNS void
	LANGUAGE plpgsql
	IMMUTABLE STRICT
	AS $$
BEGIN
	-- Does nothing, currently.
END;
$$;

COMMENT ON FUNCTION finish_run IS 'Finish_run should be called when an entire run is completed.';
-- }}}
-- {{{ Stage
CREATE OR REPLACE PROCEDURE stage ()
LANGUAGE plpgsql
AS $$
BEGIN
	IF to_regclass ('advisory_import') IS NOT NULL THEN
		TRUNCATE advisory_import;
		TRUNCATE advisory_import_to_copy;
		CALL matcher_v2_meta.emit_log ('import', 'reset temporary tables');
	ELSE
		CREATE TEMPORARY TABLE advisory_import OF advisory_import_row ON COMMIT DROP;
		--ALTER TABLE advisory_import
			--ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY;
		CREATE TEMPORARY TABLE advisory_import_to_copy (
			id BIGINT
		) ON COMMIT DROP;
		CALL matcher_v2_meta.emit_log ('import', 'created temporary tables');
	END IF;
END;
$$;

COMMENT ON PROCEDURE stage IS $$Stage prepares the 'advisory_import' table for use with 'advisory_import_commit' and 'advisory_import_finish'.$$;
-- }}}
-- {{{ Commit_add
CREATE OR REPLACE PROCEDURE commit_add(run_id BIGINT, upd_id BIGINT, upd_run_id BIGINT)
	LANGUAGE plpgsql
	AS $$
DECLARE
	ev JSONB := jsonb_build_object('run', run_id, 'updater', upd_id, 'update_run', upd_run_id);
BEGIN
	-- TODO(hank) Experiment with adding additional writeback fields for the latter imports.

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"advisory"'));
	MERGE INTO matcher_v2.advisory AS tgt
	USING (
		SELECT
			upd_id AS updater, (advisory).name AS name
		FROM
			advisory_import) AS src ON tgt.updater = src.updater
		AND tgt.name = src.name
	WHEN MATCHED THEN
		UPDATE SET
			generation = run_id
	WHEN NOT MATCHED THEN
		INSERT (updater, name, generation, added)
			VALUES (src.updater, src.name, run_id, run_id);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"advisory"'));

	CALL matcher_v2_meta.emit_log ('import', 'update start', jsonb_insert(ev, '{table}', '"advisory_import"'));
	-- Write back the advisory IDs to make the subsequent MERGE statements simpler.
	UPDATE
		advisory_import AS i
	SET
		advisory_id = adv.id
	FROM
		matcher_v2.advisory AS adv
	WHERE (i.advisory).name = adv.name
		AND adv.updater = upd_id
		AND adv.generation = run_id;
	CALL matcher_v2_meta.emit_log ('import', 'update done', jsonb_insert(ev, '{table}', '"advisory_import"'));

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"advisory_meta"'));
	MERGE INTO matcher_v2.advisory_meta AS tgt
	USING (
		SELECT
			upd_id AS updater, adv.id AS advisory, i.*
		FROM
			matcher_v2.advisory AS adv
			JOIN (
				SELECT
					(advisory).*
				FROM
					advisory_import) AS i ON i.name = adv.name
				WHERE
					upd_id = adv.updater
					AND run_id = adv.generation) AS src ON tgt.advisory = src.advisory
	WHEN MATCHED
		AND ROW (src) IS NOT DISTINCT FROM ROW (tgt) THEN
			DO NOTHING
	WHEN MATCHED THEN
		UPDATE SET
			issued = src.issued, summary = src.summary, description = src.description, uri = src.uri, severity = src.severity, normalized_severity = src.normalized_severity
	WHEN NOT MATCHED THEN
		INSERT (advisory, issued, summary, description, uri, severity, normalized_severity)
			VALUES (src.advisory, src.issued, src.summary, src.description, src.uri, src.severity, src.normalized_severity);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"advisory_meta"'));

	-- Reference
	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"reference"'));
	MERGE INTO matcher_v2.reference AS tgt
	USING (
		SELECT
			(unnest(reference)).*
			FROM
				advisory_import) AS src ON tgt.namespace = src.namespace
		AND tgt.name = src.name
	WHEN MATCHED
		AND src.uri = tgt.uri THEN
			DO NOTHING
	WHEN MATCHED THEN
		UPDATE SET
			uri = matcher_v2_import.array_distinct (tgt.uri || src.uri)
	WHEN NOT MATCHED THEN
		INSERT (namespace, name, uri)
			VALUES (src.namespace, src.name, src.uri);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"reference"'));

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"advisory_reference"'));
	MERGE INTO matcher_v2.advisory_reference AS tgt
	USING (
		SELECT
			i.advisory_id AS advisory, r.id AS reference
		FROM
			matcher_v2.reference r
			JOIN (
				SELECT
					advisory_id, unnest(reference) AS ref
					FROM
						advisory_import) AS i ON ((i.ref).name = r.name
							AND (i.ref).namespace = r.namespace)) AS src ON tgt.advisory = src.advisory
		AND tgt.reference = src.reference
	WHEN MATCHED THEN
			DO NOTHING
	WHEN NOT MATCHED THEN
			INSERT
				(advisory, reference)
				VALUES (src.advisory, src.reference);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"advisory_reference"'));

	-- Package
	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"package_name"'));
	MERGE INTO matcher_v2.package_name AS tgt
	USING (
		SELECT
			DISTINCT
				(unnest(package)).name
				FROM
					advisory_import) AS src ON tgt.name = src.name
	WHEN MATCHED THEN
			DO NOTHING
	WHEN NOT MATCHED THEN
		INSERT (name)
			VALUES (src.name);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"package_name"'));

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"package"'));
	MERGE INTO matcher_v2.package AS tgt
	USING (
		SELECT
			i.advisory_id, n.id AS name_id, (i.pkg).*
		FROM (
			SELECT
				advisory_id, unnest(package) AS pkg
				FROM
					advisory_import) AS i
					JOIN matcher_v2.package_name AS n ON ((i.pkg).name = n.name)) AS src ON tgt.advisory = src.advisory_id
			AND tgt.name = src.name_id
			AND tgt.kind = src.kind
	WHEN MATCHED
		AND ROW (tgt) IS NOT DISTINCT FROM ROW (src) THEN
			DO NOTHING
	WHEN MATCHED THEN
		UPDATE SET
			arch = src.arch, vulnerable_range = src.vulnerable_range, version_upstream = src.version_upstream, version_kind = src.version_kind, purl = src.purl, cpe = src.cpe
	WHEN NOT MATCHED THEN
		INSERT (advisory, name, kind, arch, vulnerable_range, version_upstream, version_kind, purl, cpe)
			VALUES (src.advisory_id, src.name_id, src.kind, src.arch, src.vulnerable_range, src.version_upstream, src.version_kind, src.purl, src.cpe);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"package"'));

	-- Attr
	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"mediatype"'));
	MERGE INTO matcher_v2.mediatype AS tgt
	USING (
		SELECT
			DISTINCT
				(unnest(attr)).mediatype
				FROM
					advisory_import) AS src ON tgt.mediatype = src.mediatype
	WHEN MATCHED THEN
			DO NOTHING
	WHEN NOT MATCHED THEN
		INSERT (mediatype)
			VALUES (src.mediatype);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"mediatype"'));

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"attr"'));
	MERGE INTO matcher_v2.attr AS tgt
	USING (
		SELECT
			mt.id AS mediatype, i.data AS data
		FROM (
			SELECT
				DISTINCT
					(unnest(attr)).*
					FROM
						advisory_import) AS i
						JOIN matcher_v2.mediatype AS mt ON i.mediatype = mt.mediatype) AS src ON tgt.mediatype = src.mediatype
			AND tgt.data = src.data
	WHEN MATCHED THEN
			DO NOTHING
	WHEN NOT MATCHED THEN
			INSERT
				(mediatype, data)
				VALUES (src.mediatype, src.data);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"attr"'));

	CALL matcher_v2_meta.emit_log ('import', 'merge start', jsonb_insert(ev, '{table}', '"advisory_attr"'));
	MERGE INTO matcher_v2.advisory_attr AS tgt
	USING (
		SELECT
			i.advisory_id AS advisory, a.id AS attr
		FROM (
			SELECT
				advisory_id, (unnest(attr)).*
				FROM
					advisory_import) AS i
					JOIN (
						SELECT
							attr.id AS id, mediatype.mediatype AS mediatype, attr.data AS data
						FROM
							matcher_v2.attr
							JOIN matcher_v2.mediatype ON mediatype.id = attr.mediatype) AS a ON i.mediatype = a.mediatype
								AND i.data = a.data) AS src ON tgt.advisory = src.advisory
		AND tgt.attr = src.attr
	WHEN MATCHED THEN
			DO NOTHING
	WHEN NOT MATCHED THEN
			INSERT
				(advisory, attr)
				VALUES (src.advisory, src.attr);
	CALL matcher_v2_meta.emit_log ('import', 'merge done', jsonb_insert(ev, '{table}', '"advisory_attr"'));

	CALL matcher_v2_meta.emit_log ('import', 'truncating input table', jsonb_insert(ev, '{table}', '"advisory_import"'));
	TRUNCATE advisory_import;
END;
$$;

COMMENT ON PROCEDURE commit_add(BIGINT, BIGINT, BIGINT) IS 'Commit_add adds all the provided data to the current run.';
-- }}}
-- {{{ Commit_snapshot
CREATE OR REPLACE PROCEDURE commit_snapshot(run_id BIGINT, upd_id BIGINT, upd_run_id BIGINT)
	LANGUAGE plpgsql
	AS $$
DECLARE
	ev JSONB := jsonb_build_object('run', run_id, 'updater', upd_id, 'update_run', upd_run_id);
BEGIN
	-- It seems like it'd be easier to just bump the generation for everything
	-- (and I agree), but we'd need to keep track of the previous state and
	-- restore that if the relevant advisory is named in a subsequent remove.
	CALL matcher_v2_meta.emit_log ('import', 'insert start', jsonb_insert(ev, '{table}', '"advisory_import_to_copy"'));
	WITH prev AS (
		SELECT
			run
		FROM
			matcher_v2.updater_run
		WHERE
			updater = upd_id
			AND run < run_id
			AND success
		ORDER BY
			id DESC
		LIMIT 1)
	INSERT INTO advisory_import_to_copy
	SELECT
		id
	FROM
		matcher_v2.advisory,
		prev
	WHERE
		updater = upd_id
		AND generation = prev.run;
	CALL matcher_v2_meta.emit_log ('import', 'insert done', jsonb_insert(ev, '{table}', '"advisory_import_to_copy"'));

	CALL matcher_v2_meta.emit_log ('import', 'truncating input table', jsonb_insert(ev, '{table}', '"advisory_import"'));
	TRUNCATE advisory_import;
END;
$$;

COMMENT ON PROCEDURE commit_snapshot(BIGINT, BIGINT, BIGINT) IS 'Commit_snapshot copies all advisories from the latest successful update run to the current run.';
-- }}}
-- {{{ Commit_remove
CREATE OR REPLACE PROCEDURE commit_remove(run_id BIGINT, upd_id BIGINT, upd_run_id BIGINT)
	LANGUAGE plpgsql
	AS $$
DECLARE
	ev JSONB := jsonb_build_object('run', run_id, 'updater', upd_id, 'update_run', upd_run_id);
BEGIN
	CALL matcher_v2_meta.emit_log ('import', 'delete start', jsonb_insert(ev, '{table}', '"advisory_import_to_copy"'));
	DELETE FROM advisory_import_to_copy
	WHERE id IN (
			SELECT
				a.id
			FROM
				matcher_v2.advisory AS a
				JOIN advisory_import AS i ON a.name = i.name
			WHERE
				updater = upd_id);
	CALL matcher_v2_meta.emit_log ('import', 'delete done', jsonb_insert(ev, '{table}', '"advisory_import_to_copy"'));

	CALL matcher_v2_meta.emit_log ('import', 'truncating input table', jsonb_insert(ev, '{table}', '"advisory_import"'));
	TRUNCATE advisory_import;
END;
$$;

COMMENT ON PROCEDURE commit_remove(BIGINT, BIGINT, BIGINT) IS 'Commit_remove removes the named advisories from the current run. All other data in the table is not considered.';
-- }}}
-- {{{ Finish
CREATE OR REPLACE PROCEDURE finish (run_id BIGINT, upd_id BIGINT, upd_run_id BIGINT)
	LANGUAGE plpgsql
	AS $$
DECLARE
	ev JSONB;
BEGIN
	ev := jsonb_build_object('run', run_id, 'updater', upd_id, 'update_run', upd_run_id);
	CALL matcher_v2_meta.emit_log ('import', 'update start', jsonb_insert(ev, '{table}', '"advisory"'));
	UPDATE
		matcher_v2.advisory
	SET
		generation = run_id
	FROM
		advisory_import_to_copy AS c
	WHERE
		c.id = advisory.id;
	CALL matcher_v2_meta.emit_log ('import', 'update done', jsonb_insert(ev, '{table}', '"advisory"'));
	CALL matcher_v2_meta.emit_log ('import', 'truncating input table', jsonb_insert(ev, '{table}', '"advisory_import_to_copy"'));
	TRUNCATE advisory_import_to_copy;

	CALL matcher_v2_meta.emit_log ('import', 'ANALYZE start');
	ANALYZE matcher_v2.advisory,
	matcher_v2.advisory_meta,
	matcher_v2.reference,
	matcher_v2.advisory_reference,
	matcher_v2.package,
	matcher_v2.package_name,
	matcher_v2.mediatype,
	matcher_v2.attr,
	matcher_v2.advisory_attr;
	CALL matcher_v2_meta.emit_log ('import', 'ANALYZE done');
END;
$$;

COMMENT ON PROCEDURE finish (BIGINT, BIGINT, BIGINT) IS 'Finish updates advisory generations as needed and performs ANALYZE on the new data.';
-- }}}
DO LANGUAGE plpgsql
$$
BEGIN
	CALL matcher_v2_meta.emit_log ('init', 'matcher_v2_import schema populated');
END
$$;
