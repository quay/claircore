package dnf

import _ "embed" // embed sql

//go:generate find sql -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --fix --language sqlite {} ;

var (
	// Return one column containing the repoid.
	// Takes five arguments, in order:
	//   - name
	//   - epoch
	//   - version
	//   - release
	//   - arch
	//
	//go:embed sql/dnf4_repoid_for_package.sql
	dnf4RepoidForPackage string

	// Return one column containing the repoids.
	//
	//go:embed sql/dnf4_all_repoids.sql
	dnf4AllRepoids string
)

var (
	// Return one column containing the repoid.
	// Takes five arguments, in order:
	//   - name
	//   - epoch
	//   - version
	//   - release
	//   - arch
	//
	//go:embed sql/dnf5_repoid_for_package.sql
	dnf5RepoidForPackage string

	// Return one column containing the repoids.
	//
	//go:embed sql/dnf5_all_repoids.sql
	dnf5AllRepoids string
)

// Report the names of tables in the database.
//
//go:embed sql/get_tables.sql
var getTables string

// Queries holds the sql needed to examine the dnf database.
type queries struct {
	AllRepoids       string
	RepoidForPackage string
}

var (
	dnf4Queries = queries{
		AllRepoids:       dnf4AllRepoids,
		RepoidForPackage: dnf4RepoidForPackage,
	}
	dnf5Queries = queries{
		AllRepoids:       dnf5AllRepoids,
		RepoidForPackage: dnf5RepoidForPackage,
	}
)
