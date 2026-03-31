package rpm

type dbKind uint

//go:generate go tool stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    // bdb
	kindSQLite // sqlite
	kindNDB    // ndb
)
