package migrations

const (
	// recent changes to the pyup updater were made.
	// since pyup updates their sec-db slowly, this
	// bumps out any existing fingerprint associated
	// with the pyup sec-db and forces a re-fetch
	// and re-download by the updater code.
	migration3 = `
UPDATE update_operation SET fingerprint = '' WHERE updater = 'pyupio';
`
)
