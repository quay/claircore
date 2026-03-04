package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/quay/claircore/toolkit/types"
)

func registerPackageKind(ctx context.Context, c *pgx.Conn) error {
	tm := c.TypeMap()
	tm.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{
		packageKindWrapEncodePlan,
	}, tm.TryWrapEncodePlanFuncs...)
	tm.TryWrapScanPlanFuncs = append([]pgtype.TryWrapScanPlanFunc{
		packageKindWrapScanPlan,
	}, tm.TryWrapScanPlanFuncs...)
	return nil
}

var (
	_ pgtype.TextScanner = (*PackageKind)(nil)
	_ pgtype.TextValuer  = PackageKind(0)
)

// PackageKind is a wrapper around [types.PackageKind].
type PackageKind types.PackageKind

// ScanText implements [pgtype.TextScanner].
func (p *PackageKind) ScanText(v pgtype.Text) error {
	if !v.Valid {
		*p = PackageKind(types.Unknown)
		return nil
	}
	text := []byte(strings.ToLower(v.String))
	return (*types.PackageKind)(p).UnmarshalText(text)
}

// TextValue implements [pgtype.TextValuer].
func (p PackageKind) TextValue() (t pgtype.Text, err error) {
	t.Valid = true
	if k := (types.PackageKind)(p); k != types.UnknownPackage {
		t.String = k.String()
	}
	return t, nil
}

// GoString implements [fmt.GoStringer].
func (p PackageKind) GoString() string {
	return fmt.Sprintf(`types.PackageKind(0x%02x)`, uint(p))
}

func packageKindWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	switch k := value.(type) {
	case types.PackageKind:
		return &wrapPackageKindEncodePlan{}, PackageKind(k), true
	case *types.PackageKind:
		return &wrapPackageKindEncodePlan{}, PackageKind(*k), true
	}
	return nil, nil, false
}

type wrapPackageKindEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapPackageKindEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return p.next.Encode(PackageKind(value.(types.PackageKind)), buf)
}

func packageKindWrapScanPlan(target any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	if p, ok := target.(*types.PackageKind); ok {
		return &wrapPackageKindScanPlan{}, (*PackageKind)(p), true
	}
	return nil, nil, false
}

type wrapPackageKindScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (p *wrapPackageKindScanPlan) Scan(src []byte, dst any) error {
	return p.next.Scan(src, (*PackageKind)(dst.(*types.PackageKind)))
}
