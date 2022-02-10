package migrations

const (
	// this migration modifies the database to add a
	// table to record update times
	migration6 = `
-- updater_status is a table keeping a record of when updaters were last checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS updater_status (
	updater_name TEXT PRIMARY KEY,
	last_attempt TIMESTAMP WITH TIME ZONE DEFAULT now(),
	last_success TIMESTAMP WITH TIME ZONE,
	last_run_succeeded BOOL,
    last_attempt_fingerprint TEXT,
    last_error TEXT
);
`
)
