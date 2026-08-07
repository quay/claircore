package types

import (
	"context"
	"unique"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func registerUniqueString(ctx context.Context, c *pgx.Conn) error {
	tm := c.TypeMap()
	tm.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{
		uniqueStringWrapEncodePlan,
	}, tm.TryWrapEncodePlanFuncs...)
	return nil
}

func uniqueStringWrapEncodePlan(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	switch v := value.(type) {
	case []unique.Handle[string]:
		return &wrapUniqueStringSliceEncodePlan{}, pgtype.FlatArray[unique.Handle[string]](v), true
	case unique.Handle[string]:
		return &wrapUniqueStringEncodePlan{}, "", true
	}
	return nil, nil, false
}

type wrapUniqueStringSliceEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapUniqueStringSliceEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return p.next.Encode(pgtype.FlatArray[unique.Handle[string]](value.([]unique.Handle[string])), buf)
}

type wrapUniqueStringEncodePlan struct {
	encodeWrapper
}

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (p *wrapUniqueStringEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return p.next.Encode(value.(unique.Handle[string]).Value(), buf)
}
