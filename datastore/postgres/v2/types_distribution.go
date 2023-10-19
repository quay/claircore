package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore"
)

func distributionWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch target.(type) {
	case *claircore.Distribution:
		return &wrapDistributionScanPlan{}, pgtype.CompositeFields{}, true
	}
	return nil, nil, false
}

type wrapDistributionScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapDistributionScanPlan) Scan(src []byte, target any) error {
	d := target.(*claircore.Distribution)
	fs := pgtype.CompositeFields{
		&d.ID,
		&d.Name,
		&d.DID,
		&d.Version,
		&d.VersionCodeName,
		&d.VersionID,
		&d.Arch,
		&d.CPE,
		&d.PrettyName,
	}
	return p.next.Scan(src, fs)
}
