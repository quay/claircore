package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore"
)

func fileWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch target.(type) {
	case *claircore.File:
		return &wrapFileScanPlan{}, pgtype.CompositeFields{}, true
	}
	return nil, nil, false
}

type wrapFileScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapFileScanPlan) Scan(src []byte, target any) error {
	f := target.(*claircore.File)
	fs := pgtype.CompositeFields{
		&f.Path,
		&f.Kind,
	}
	return p.next.Scan(src, fs)
}
