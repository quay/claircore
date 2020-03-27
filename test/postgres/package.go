package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
)

// InsertUniquePackages inserts each unique package into the database. Nested distribution and source packages
// are un nested and inserted. The pkgs array should be created by a call to GenUniquePackages
func InsertPackages(db *sqlx.DB, pkgs []*claircore.Package) error {
	for _, pkg := range pkgs {
		// index source packages
		_, err := db.Exec(`INSERT INTO package (id, kind, name, version, module) VALUES ($1, $2, $3, $4, $5)`,
			&pkg.Source.ID, &pkg.Source.Kind, &pkg.Source.Name, &pkg.Source.Version, &pkg.Source.Module)
		if err != nil {
			return fmt.Errorf("failed to index test pacakge's source %v: %v", pkg.Source, err)
		}

		// index package
		_, err = db.Exec(`INSERT INTO package (id, kind, name, version, module) VALUES ($1, $2, $3, $4, $5)`,
			&pkg.ID, &pkg.Kind, &pkg.Name, &pkg.Version, &pkg.Module)
		if err != nil {
			return fmt.Errorf("failed to insert test package %v: %v", pkg, err)
		}
	}

	return nil
}
