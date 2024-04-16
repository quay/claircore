package rhel

import (
	"context"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	_ indexer.Resolver = (*Resolver)(nil)
)

type Resolver struct{}

// Resolve takes a claircore.IndexReport and uses the rpm Files
// to determine if the package originated from an RPM. If the package
// was deemed to have been installed via RPM, it isn't included in the
// final report.
func (r *Resolver) Resolve(ctx context.Context, ir *claircore.IndexReport, layers []*claircore.Layer) *claircore.IndexReport {
	for pkgID, pkg := range ir.Packages {
		isRPMPackage := false
	envLoop:
		for _, env := range ir.Environments[pkgID] {
			if env == nil {
				continue
			}
			for _, rID := range env.RepositoryIDs {
				r := ir.Repositories[rID]
				if r.Key == repositoryKey {
					isRPMPackage = true
					break envLoop
				}
			}
		}
		if !isRPMPackage {
		filesLoop:
			for _, fs := range ir.Files {
				for _, f := range fs {
					if f.Kind == claircore.FileKindRPM && f.Path == pkg.Filepath {
						zlog.Debug(ctx).
							Str("package name", pkg.Name).
							Str("package file", pkg.Filepath).
							Str("rpm file", f.Path).
							Msg("package determined to have come from RPM, deleting")
						delete(ir.Packages, pkgID)
						delete(ir.Environments, pkgID)
						break filesLoop
					}
				}
			}
		}
	}
	return ir
}
