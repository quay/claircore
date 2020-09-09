# LibVuln Store
The Store interface implements all necessary persistence methods for LibVuln to provide its functionality.

```go
// Store aggregates all interface types
type Store interface {
	Updater
	Vulnerability
}

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database.
type Updater interface {
	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
	// vulnerabilities, and ensures vulnerabilities from previous updates are
	// not queried by clients.
	UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error)
	// GetUpdateOperations returns a list of UpdateOperations in date descending
	// order for the given updaters.
	//
	// The returned map is keyed by Updater implementation's unique names.
	//
	// If no updaters are specified, all UpdateOperations are returned.
	GetUpdateOperations(context.Context, ...string) (map[string][]driver.UpdateOperation, error)

	// GetLatestUpdateRefs reports the latest update reference for every known
	// updater.
	GetLatestUpdateRefs(context.Context) (map[string][]driver.UpdateOperation, error)
	// GetLatestUpdateRef reports the latest update reference of any known
	// updater.
	GetLatestUpdateRef(context.Context) (uuid.UUID, error)
	// DeleteUpdateOperations removes an UpdateOperation.
	DeleteUpdateOperations(context.Context, ...uuid.UUID) error
	// GetUpdateOperationDiff reports the UpdateDiff of the two referenced
	// Operations.
	//
	// In diff(1) terms, this is like
	//
	//	diff prev cur
	//
	GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)
}

// GetOpts provides instructions on how to
// match your packages to vulnerabilities.
type GetOpts struct {
	// Matchers tells the Get() method to limit the returned vulnerabilities by the provided MatchConstraint
	// see MatchConstraint type def for more info.
	Matchers []driver.MatchConstraint
	// Debug asks the database layer to log exta information
	Debug bool
	// VersionFiltering enables filtering based on the normalized versions in
	// the database.
	VersionFiltering bool
}

type Vulnerability interface {
	// get finds the vulnerabilities which match each package provided in the packages array
	// this maybe a one to many relationship. each package is assumed to have an ID.
	// a map of Package.ID => Vulnerabilities is returned.
	Get(ctx context.Context, records []*claircore.IndexRecord, opts GetOpts) (map[string][]*claircore.Vulnerability, error)
}
```
