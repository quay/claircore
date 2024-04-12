package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/toolkit/types/cpe"
)

func cpeWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	if _, ok := value.(*cpe.WFN); ok {
		return &wrapCpeEncodePlan{}, new(string), true
	}
	return nil, nil, false
}

type wrapCpeEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (*wrapCpeEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	wfn := value.(*cpe.WFN)
	if wfn == nil || wfn.Valid() != nil {
		return nil, nil
	}
	return append(buf, wfn.BindFS()...), nil
}

// BUG(hank) The configured ScanPlan for the CPE type is currently unused for
// reasons I don't quite understand. I suspect the
// [github.com/quay/claircore/toolkit/types/cpe.WFN.Scan] method is taking
// precedence.

func cpeWrapScanPlan(value any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	if _, ok := value.(*cpe.WFN); ok {
		return &wrapCpeScanPlan{}, new(string), true
	}
	return nil, nil, false
}

type wrapCpeScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (*wrapCpeScanPlan) Scan(src []byte, target any) error {
	if len(src) == 0 { // NULL?
		return nil
	}
	wfn := target.(*cpe.WFN)
	return wfn.UnmarshalText(src)
}
