package postgres

import (
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/quay/claircore"
)

func indexreportWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	switch value.(type) {
	case *claircore.IndexReport:
		return &wrapIndexreportEncodePlan{}, ([]byte)(nil), true
	}
	return nil, nil, false
}

type wrapIndexreportEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapIndexreportEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	b, err := json.Marshal(value.(*claircore.IndexReport))
	if err != nil {
		return buf, err
	}
	return p.next.Encode(b, buf)
}

func indexreportWrapScanPlan(value any) (pgtype.WrappedScanPlanNextSetter, any, bool) {
	switch value.(type) {
	case *claircore.IndexReport:
		return &wrapIndexreportScanPlan{}, ([]byte)(nil), true
	}
	return nil, nil, false
}

type wrapIndexreportScanPlan struct {
	scanWrapper
}

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (*wrapIndexreportScanPlan) Scan(src []byte, target any) error {
	return json.Unmarshal(src, target)
}
