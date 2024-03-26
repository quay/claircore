package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore"
)

func repositoryWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch target.(type) {
	case *claircore.Repository:
		return &wrapRepositoryScanPlan{}, pgtype.CompositeFields{}, true
	}
	return nil, nil, false
}

type wrapRepositoryScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapRepositoryScanPlan) Scan(src []byte, target any) error {
	r := target.(*claircore.Repository)
	var cpe *string
	fs := pgtype.CompositeFields{
		&r.ID,
		&r.Name,
		&r.Key,
		&r.URI,
		&cpe,
	}
	err := p.next.Scan(src, fs)
	if cpe != nil {
		err = errors.Join(err, r.CPE.UnmarshalText([]byte(*cpe)))
	}
	return err
}
