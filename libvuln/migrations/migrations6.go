package migrations

const (
	// this migration modifies the database to add a
	// table to record update times
	migration6 = `
-- update_time is a table keeping a record of when updaters were last checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS update_time (
	updater_name TEXT PRIMARY KEY,
	last_update_time TIMESTAMP WITH TIME ZONE DEFAULT now()
);
`
)
