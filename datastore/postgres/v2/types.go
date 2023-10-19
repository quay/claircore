package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// All the types_*.go files are helpers for various local types.
//
// They're all in separate files because the additional types can get noisy.

var (
	newWrapEncodePlans = []pgtype.TryWrapEncodePlanFunc{
		cpeWrapEncodePlan,
		indexreportWrapEncodePlan,
	}
	newWrapScanPlans = []pgtype.TryWrapScanPlanFunc{
		cpeWrapScanPlan,
		indexreportWrapScanPlan,
		distributionWrapScanPlan,
		fileWrapScanPlan,
		repositoryWrapScanPlan,
	}
)

func connectRegisterTypes(ctx context.Context, c *pgx.Conn) error {
	m := c.TypeMap()
	m.TryWrapEncodePlanFuncs = append(newWrapEncodePlans, m.TryWrapEncodePlanFuncs...)
	m.TryWrapScanPlanFuncs = append(newWrapScanPlans, m.TryWrapScanPlanFuncs...)

	replaceUUID(m) // Infallible

	// I assume we'll need more of these in the future.
	for _, f := range []func(context.Context, *pgx.Conn) error{
		registerVersionRange,
	} {
		if err := f(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// EncodeWrapper is an embeddable type to implement SetNext for free.
type encodeWrapper struct {
	next pgtype.EncodePlan
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *encodeWrapper) SetNext(next pgtype.EncodePlan) { w.next = next }

// ScanWrapper is an embeddable type to implement SetNext for free.
type scanWrapper struct {
	next pgtype.ScanPlan
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *scanWrapper) SetNext(next pgtype.ScanPlan) { w.next = next }
