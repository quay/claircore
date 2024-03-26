// Package postgres contains testing helpers for PostgreSQL databases.
//
// Most of the functions provide independent implementations of functionality
// that the datastore/postgres package does internally in its exposed API.
// This package uses `pgx/v5` instead of `pgx/v4`.
//
// # Test Databases
//
// The [TestIndexerDB] and [TestMatcherDB] start database engines and create
// suitable databases as needed. See the [test/integration] package for more
// information on the specifics of the former.
//
// As part of the database setup, these functions can load SQL files. This
// package searches both its embedded copy of the local "sql" directory and the
// main test package's "testdata" director for these patterns:
//   - all_*.psql
//   - matcher_*.psql (for [TestMatcherDB])
//   - indexer_*.psql (for [TestIndexerDB])
package postgres
