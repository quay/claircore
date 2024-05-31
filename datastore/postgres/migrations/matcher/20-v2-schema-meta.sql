-- vim: set foldmethod=marker :
-- It's dangerous to go alone! Take this.
-- https://www.postgresql.org/docs/current/plpgsql.html
CREATE SCHEMA matcher_v2_meta;

COMMENT ON SCHEMA matcher_v2_meta IS $$
Matcher_v2_meta is data about objects in the matcher_v2 table.

Needs to have the "housekeeping" function called at least weekly.
$$;

SET
  LOCAL search_path TO matcher_v2_meta,
  "$user",
  public;

-- {{{ Meta
CREATE OR REPLACE FUNCTION config_fingerprint (cfg JSONB) RETURNS BYTEA IMMUTABLE STRICT PARALLEL SAFE LANGUAGE SQL AS $$
	SELECT
		sha256 (convert_to(cfg #>> '{}', 'utf8'));
$$;

COMMENT ON FUNCTION config_fingerprint (JSONB) IS 'Meta_config_fingerprint computes a fingerprint for the supplied JSONB.';

CREATE OR REPLACE FUNCTION config_fingerprint (cfg TEXT) RETURNS BYTEA IMMUTABLE STRICT PARALLEL SAFE LANGUAGE SQL AS $$
	SELECT
		matcher_v2_meta.config_fingerprint (to_jsonb (cfg));
$$;

COMMENT ON FUNCTION config_fingerprint (TEXT) IS $$
Meta_config_fingerprint computes a fingerprint for the supplied JSON-formatted text.

This function converts the input to JSONB internally, so it's better to use the function that accepts JSONB directly if you have it.
$$;

CREATE TABLE config (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  config JSONB,
  fingerprint BYTEA GENERATED ALWAYS AS (matcher_v2_meta.config_fingerprint (config)) STORED
);

COMMENT ON TABLE config IS $$
Meta_config holds configuration for parts of the matcher database itself.

This is implemented in-database (instead of relying on parameters being passed for every function) to help with observability.
$$;

CREATE OR REPLACE FUNCTION latest_config () RETURNS JSONB LANGUAGE SQL AS $$
	SELECT
		config
	FROM
		matcher_v2_meta.config
	ORDER BY
		id DESC
	LIMIT 1
$$;

COMMENT ON FUNCTION latest_config IS 'Latest_config returns the latest config.';

CREATE TABLE log(
  id BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL, -- NB *not* PRIMARY KEY
  pid BIGINT NOT NULL DEFAULT pg_backend_pid(),
  ts TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT clock_timestamp(),
  kind TEXT,
  event JSONB,
  message TEXT,
  UNIQUE (id, ts) -- Needed for the paritioning.
)
PARTITION BY
  RANGE (ts);

COMMENT ON TABLE log IS $$
Internal log table.

Partitioned by week. Needs to have the function "housekeeping" called at least weekly.
$$;

CREATE OR REPLACE PROCEDURE emit_log (kind TEXT, message TEXT, event JSONB) LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO matcher_v2_meta.log(kind, message, event) VALUES (kind, message, event);
	RAISE INFO '%: % %', kind, message, event;
END;
$$;

CREATE OR REPLACE PROCEDURE emit_log (kind TEXT, message TEXT) LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO matcher_v2_meta.log(kind, message, event) VALUES (kind, message, NULL);
	RAISE INFO '%: %', kind, message;
END;
$$;

COMMENT ON PROCEDURE emit_log (TEXT, TEXT, JSONB) IS 'Emit_log is a helper that records a log message and uses the standard PostgreSQL logging.';

CREATE OR REPLACE FUNCTION housekeeping () RETURNS void LANGUAGE plpgsql AS $$
DECLARE
	namefmt TEXT := 'log_IYYY_IW';
	config JSONB;
	instant TIMESTAMP;
	tablename TEXT;
	removed RECORD;
	-- Config values:
	log_table_precreate INTEGER;
	log_table_keep INTEGER;
	config_keep INTEGER;
BEGIN
	config := matcher_v2_meta.latest_config ();
	SELECT
		INTO log_table_keep coalesce((config -> 'log_table_keep')::INTEGER, 2);
	SELECT
		INTO log_table_precreate coalesce((config -> 'log_table_precreate')::INTEGER, 2);
	SELECT
		INTO config_keep coalesce((config -> 'config_keep')::INTEGER, 10);
	-- Create log loop
	-- Cannot call the log function in here until after the loop has run.
	FOR w IN 0..log_table_precreate LOOP
		instant := CURRENT_TIMESTAMP + make_interval(weeks => w);
		tablename := to_char(instant, namefmt);
		IF to_regclass ('' || tablename) IS NULL THEN
			EXECUTE format('CREATE TABLE "matcher_v2_meta".%I PARTITION OF "matcher_v2_meta"."log" FOR VALUES FROM (%L) TO (%L)', tablename, date_trunc('week', instant), date_trunc('week', instant + make_interval(weeks => 1)));
			CALL matcher_v2_meta.emit_log ('meta', 'created log table', jsonb_build_object('name', tablename));
		END IF;
	END LOOP;
	-- Delete log loop
	FOR w IN REVERSE - 1.. (-1 * log_table_keep)
	LOOP
		instant := CURRENT_TIMESTAMP + make_interval(weeks => w);
		tablename := to_char(instant, namefmt);
		IF to_regclass (tablename) IS NOT NULL THEN
			EXECUTE format('DROP TABLE "matcher_v2_meta".%I', tablename);
			CALL matcher_v2_meta.emit_log ('meta', 'deleted log table', jsonb_build_object('name', tablename));
		END IF;
	END LOOP;
	-- Delete config loop
	FOR removed IN DELETE FROM matcher_v2_meta.config
	WHERE id IN (
			SELECT
				id
			FROM
				matcher_v2_meta.config
			ORDER BY
				id DESC OFFSET config_keep)
		RETURNING (id,
			fingerprint)
			LOOP
				CALL matcher_v2_meta.emit_log ('meta', 'deleted previous config', jsonb_build_object('id', removed.id, 'fingerprint', removed.fingerprint));
			END LOOP;
	CALL matcher_v2_meta.emit_log('meta', 'housekeeping run finished');
END;
$$;

COMMENT ON FUNCTION housekeeping () IS $$
Housekeeping manages the partitions of the "log" table and manages the number of rows in the "config" table.

Uses the config keys:
- log_table_precreate
  Number of weeks of logs to pre-create tables for. (default: 2)
  Setting this to 0 will almost certainly break things.
- log_table_keep
  Number of weeks of logs to keep. (default: 2)
- config_keep
  Number of config versions to keep. (default: 10)
$$;

-- }}}
DO LANGUAGE plpgsql $$
BEGIN
	PERFORM matcher_v2_meta.housekeeping ();
	CALL matcher_v2_meta.emit_log ('init', 'matcher_v2_meta schema populated');
END
$$;
