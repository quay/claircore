package postgres

// IndexerOption is an option for configuring an indexer datastore.
type IndexerOption interface {
	indexerConfig(indexerConfig) indexerConfig
}

// IndexerConfig is the actual configuration structure used in [NewIndexerV1].
type indexerConfig struct {
	Migrations   bool
	MinMigration int
}

func newIndexerConfig() indexerConfig {
	return indexerConfig{
		Migrations:   false,
		MinMigration: MinimumIndexerMigration,
	}
}
