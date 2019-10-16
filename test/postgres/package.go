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
		// // index distribution
		// _, err := db.Exec(`INSERT INTO dist (id, arch, name, version, version_code_name, version_id) VALUES ($1, $2, $3, $4, $5, $6)`,
		// 	&pkg.Dist.ID, &pkg.Dist.Arch, &pkg.Dist.Name, &pkg.Dist.Version, &pkg.Dist.VersionCodeName, &pkg.Dist.VersionID)
		// if err != nil {
		// 	return fmt.Errorf("failed to insert test distribution %v: %v", pkg.Dist, err)
		// }

		// index source packages
		_, err := db.Exec(`INSERT INTO package (id, kind, name, version) VALUES ($1, $2, $3, $4)`,
			&pkg.Source.ID, &pkg.Source.Kind, &pkg.Source.Name, &pkg.Source.Version)
		if err != nil {
			return fmt.Errorf("failed to index test pacakge's source %v: %v", pkg.Source, err)
		}

		// index package
		_, err = db.Exec(`INSERT INTO package (id, kind, name, version) VALUES ($1, $2, $3, $4)`,
			&pkg.ID, &pkg.Kind, &pkg.Name, &pkg.Version)
		if err != nil {
			return fmt.Errorf("failed to insert test package %v: %v", pkg, err)
		}
	}

	return nil
}
