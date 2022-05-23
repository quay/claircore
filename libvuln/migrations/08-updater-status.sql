CREATE TABLE IF NOT EXISTS updater_status (
	updater_name TEXT PRIMARY KEY,
	last_attempt TIMESTAMP WITH TIME ZONE DEFAULT now(),
	last_success TIMESTAMP WITH TIME ZONE,
	last_run_succeeded BOOL,
    last_attempt_fingerprint TEXT,
    last_error TEXT
);
