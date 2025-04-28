package types

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore"
)

func registerVersionRange(ctx context.Context, c *pgx.Conn) error {
	tm := c.TypeMap()
	tm.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{
		versionrangeWrapEncodePlan,
		versionWrapEncodePlan,
	}, tm.TryWrapEncodePlanFuncs...)
	tm.TryWrapScanPlanFuncs = append([]pgtype.TryWrapScanPlanFunc{
		versionrangeWrapScanPlan,
		versionWrapScanPlan,
	}, tm.TryWrapScanPlanFuncs...)

	var pgErr *pgconn.PgError
	t, err := c.LoadType(ctx, "VersionRange")
	switch {
	case errors.Is(err, nil):
		at, ok := tm.TypeForOID(pgtype.Int4ArrayOID)
		if !ok {
			return errors.New("unable to get PostgreSQL type for int4[]")
		}
		t.Codec = &pgtype.RangeCodec{ElementType: at}
		tm.RegisterType(t)
	case errors.As(err, &pgErr):
		if pgErr.Code == "42704" { // OK: "no such type"
			break
		}
		fallthrough
	default:
		return err
	}

	return nil
}

func versionWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	switch v := value.(type) {
	case *claircore.Version:
		return &wrapVersionPtrEncodePlan{}, &v.V, true
	case claircore.Version:
		return &wrapVersionEncodePlan{}, &v.V, true
	}
	return nil, nil, false
}

type wrapVersionPtrEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapVersionPtrEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return p.next.Encode(&(value.(*claircore.Version)).V, buf)
}

type wrapVersionEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapVersionEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	v := value.(claircore.Version)
	return p.next.Encode(&v.V, buf)
}

func versionWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch target.(type) {
	case *claircore.Version:
		return &wrapVersionScanPlan{}, &pgtype.FlatArray[int32]{}, true
	}
	return nil, nil, false
}

type wrapVersionScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapVersionScanPlan) Scan(src []byte, target any) error {
	a := pgtype.FlatArray[int32]{}
	err := p.next.Scan(src, &a)
	v := target.(*claircore.Version)
	copy(v.V[:], a)
	return err
}

func versionrangeWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	switch value.(type) {
	case *claircore.Range:
		return &wrapVersionrangeEncodePlan{}, (*pgtype.Range[claircore.Version])(nil), true
	}
	return nil, nil, false
}

type wrapVersionrangeEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapVersionrangeEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	cr := value.(*claircore.Range)
	r := pgtype.Range[claircore.Version]{
		Lower:     cr.Lower,
		LowerType: pgtype.Inclusive,
		Upper:     cr.Upper,
		UpperType: pgtype.Exclusive,
		Valid:     true,
	}

	return p.next.Encode(&r, buf)
}

func versionrangeWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch target.(type) {
	case *claircore.Range:
		return &wrapVersionrangeScanPlan{}, (*pgtype.Range[claircore.Version])(nil), true
	}
	return nil, nil, false
}

type wrapVersionrangeScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapVersionrangeScanPlan) Scan(src []byte, target any) error {
	var r pgtype.Range[claircore.Version]
	if err := p.next.Scan(src, &r); err != nil {
		return err
	}
	if r.IsNull() {
		return nil
	}
	switch l, u := r.BoundTypes(); {
	case l == pgtype.Empty && u == pgtype.Empty:
		return nil
	case l != pgtype.Inclusive || u != pgtype.Exclusive:
		return fmt.Errorf("bad bounds for range: %v, %v", l, u)
	}
	cr := target.(*claircore.Range)
	(*cr).Lower = r.Lower
	(*cr).Upper = r.Upper
	return nil
}
