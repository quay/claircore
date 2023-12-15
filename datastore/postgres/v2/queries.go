package postgres

import (
	"context"
	"embed"
	"io/fs"
	"path"
	"strings"

	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.opentelemetry.io/otel/trace"
)

// Queries is an embedded filesystem containing all the SQL executed by this
// package.
//
// When queries are added and removed, "go generate" must be re-run to update
// the [queryMetadata] tables.
//
//go:generate go run github.com/quay/claircore/internal/cmd/querymetadata
//go:embed queries
var queries embed.FS

// LoadQuery loads the named query from [queries] and adds the relevant
// attributes from [queryMetadata] to the tracing span.
func loadQuery(ctx context.Context, name string) string {
	b, err := fs.ReadFile(queries, path.Join("queries", name))
	if err != nil {
		panic("programmer error: bad query name: " + err.Error())
	}
	q := string(b)
	_, qname, ok := strings.Cut(path.Base(name), "_")
	if !ok {
		panic("programmer error: bad query name: no underscore")
	}
	qname = strings.TrimSuffix(qname, ".sql")
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		semconv.DBSQLTable(queryMetadata.Table[name]),
		semconv.DBStatement(q),
		semconv.DBOperation(queryMetadata.Op[name]),
	)
	return q
}
