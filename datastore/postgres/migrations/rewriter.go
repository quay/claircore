package migrations

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

var _ pgx.QueryRewriter = tableRewriter(nil)

type tableRewriter pgx.Identifier

// RewriteQuery implements [pgx.QueryRewriter].
func (t tableRewriter) RewriteQuery(_ context.Context, _ *pgx.Conn, sql string, args []any) (newSQL string, newArgs []any, err error) {
	newSQL = strings.ReplaceAll(sql, `"@table"`, pgx.Identifier(t).Sanitize())
	return newSQL, args, nil
}
