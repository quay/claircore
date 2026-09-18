// Package migrations holds PostgreSQL migrations for databases to back
// "datastore" implementations.
//
// Migration IDs must be unique project wide. Creating a migration on any branch
// "claims" that ID for all branches.
//
// This package allows for "nonsequential" and "application-driven" migrations.
// These features should almost always be avoided.
//
// # Nonsequential Migrations
//
// Nonsequential migrations allow for a migration to be applied without
// requiring every previous migration. This may be used when a migration that
// does not alter the schema, or alters it in a self-contained way, needs to be
// picked onto a "release" branch.
//
// Using this feature means that migrations are no longer simple linear
// patches, but are patches that must be [commutative]. Care must be taken that
// all precursor migrations are also present. There is no help for doing this
// in the package.
//
// # Application-Driven Migrations
//
// Application-driven migrations allow for a migration to occur outside of a
// single, blocking transaction. Such changes would be rewriting rows or
// altering constraints on large, read-heavy tables. For example, adding a
// foreign key constraint to a large table is best done with this mechanism (see
// also: [ALTER TABLE notes] about "NOT VALID" constraints).
//
// Using this feature may result in a migration being in a state where writes
// must happen in the "new" way and reads in both the "old" and "new" ways while
// the worker runs. Using this feature may result in every process polling
// migration state periodically until it's finished.
//
// Application-driven migrations are executed serially by a single process. The
// migrations could have some parallelism, but the dependencies would be too
// complex to track "correctly" for what should be a rarely-used feature.
// Additionally, migrations are responsible for their own concurrency and
// idempotentcy; generally they should be written with an eye to minimizing
// locking and working incrementally.
//
// # Feature Flags
//
// Individual migrations (or interdependent migrations) should be thought of as
// "feature flags." That is, there should be code to handle both presence and
// absence of the migration. See [IndexerMigrations] and [MatcherMigrations] for
// retrieving this information.
//
// It's recommended that the database code remove these divergent paths and
// update the required minimum migration on every minor release. Column and
// table deletion should also be postponed to these "checkpoints".
//
// # SQL Files
//
// SQL files in this package are applied in numerical order, using the segment
// before the first "-" as the identifier.
//
// If files end in ".start.sql" then the migration is marked as
// "application-driven". See [IndexerFinishMigration] and
// [MatcherFinishMigration] to explain how to run application logic to finish
// migrations.
//
// As a convention, the file "checkpoint.sql.next" is used to accumulate changes
// that should happen in the next "checkpoint" release.
//
// # DDL
//
// The SQL definition reference in the following sections does NOT mean database
// structure is considered public API. Users MUST NOT rely on a certain database
// structure.
//
// [commutative]: https://en.wikipedia.org/wiki/Commutative_property
// [ALTER TABLE notes]: https://www.postgresql.org/docs/current/sql-altertable.html#SQL-ALTERTABLE-NOTES
package migrations
