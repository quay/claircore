CREATE TABLE IF NOT EXISTS updater_status (
    updater_name text PRIMARY KEY,
    last_attempt timestamp with time zone DEFAULT now(),
    last_success timestamp with time zone,
    last_run_succeeded bool,
    last_attempt_fingerprint text,
    last_error text
);
