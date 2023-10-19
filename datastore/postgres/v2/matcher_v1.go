package postgres

type MatcherOption interface {
	matcherConfig(matcherConfig) matcherConfig
}

type matcherConfig struct {
	Migrations   bool
	MinMigration int
}

func newMatcherConfig() matcherConfig {
	return matcherConfig{
		Migrations:   false,
		MinMigration: MinimumMatcherMigration,
	}
}
