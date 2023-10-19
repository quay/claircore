// Package postgres implements the indexer and matcher datastore interfaces for
// a PostgreSQL database.
//
// This package is an attempt to learn all the lessons from writing the previous
// postgres database package. Some things this package does that the "v1"
// package doesn't:
//
//   - Makes aggressive use of closures
//   - Makes aggressive use of helper thunks
//   - Makes aggressive use of the database driver
//   - Removes inline SQL
//   - Uniformly incorporates traces and metrics
//   - Keeps API together in the source
//
// It's hoped that these changes will keep this package more maintainable over
// time.
//
// # Telemetry
//
// This package has strict conventions for function boilerplate. See the
// comments in "doc.go" for more information. This package tries to follow the
// [OpenTelemetry Database Metrics] specification where it can.
//
// Currently implemented metrics:
//
//   - db.client.connections.idle.max
//   - db.client.connections.idle.min
//   - db.client.connections.max
//   - db.client.connections.pending_requests
//   - db.client.connections.timeouts
//   - db.client.connections.usage
//   - db.client.connections.use_time
//   - db.client.connections.create_time
//
// Currently NOT implemented metrics:
//
//   - db.client.connections.wait_time
//
// In addition, the following metrics are exposed:
//
//   - method.calls
//   - method.call_time
//
// See the exported descriptions for details.
//
// The following attributes are added to spans where relevant:
//
//   - db.rows_affected
//
// # Queries
//
// SQL statements should be arranged in files in the "queries" directory. Those
// files should be formatted by `pg_format -T -L`.
//
// # Boilerplate
//
// Boilerpate functions are implemented by the "storeCommon" type. The command
//
//	go doc -u -all storeCommon
//
// should provide usage information for developers.
//
// # Tests
//
// This package has automated tests to try to avoid Sequential Scan query plans.
// New queries are not allowed to be added to the exception list; add an index
// or rewrite the query. Queries should endeavor to do work database-side, as
// opposed to making queries to construct further queries.
//
// This package provides some helper SQL functions in the test environment, see
// the "testdata" directory.
//
// [OpenTelemetry Database Metrics]: https://opentelemetry.io/docs/specs/semconv/database/database-metrics/
package postgres // import "github.com/quay/claircore/datastore/postgres/v2"
