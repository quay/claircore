package rpm

type dbKind uint

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    // bdb
	kindSQLite // sqlite
	kindNDB    // ndb
)
