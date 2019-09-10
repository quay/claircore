package updater

// Updater is an aggregate interface combining the method set of a Fetcher and a Parser
// and forces a Name() to be provided
type Updater interface {
	Name() string
	Fetcher
	Parser
}
