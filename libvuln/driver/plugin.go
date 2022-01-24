package driver

const (
	// MatcherEntrypoint is the variable name that is used as an entrypoint for
	// matcher plugins. This variable must implement the MatcherFactory
	// interface.
	//
	// The "Matchers" method will be called for every Libvuln construction in
	// the program. This usually happens only once, but plugins should guard
	// against repeated calls if it affects correctness.
	MatcherEntrypoint = `MatcherFactory`

	// EnricherEntrypoint ...
	EnricherEntrypoint = `Enricher`

	// UpdaterEntrypoint ...
	UpdaterEntrypoint = `UpdaterSetFactory`
)

// DocumentationHelper ...
type DocumentationHelper interface {
	DocumentationURL() string
}
