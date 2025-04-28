package types

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func ConnectRegisterTypes(ctx context.Context, c *pgx.Conn) error {
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
