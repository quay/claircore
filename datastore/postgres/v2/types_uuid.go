package postgres

import (
	"database/sql/driver"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RegisterUUID replaces the default of using [pgtype.UUID] with using
// [uuid.UUID].
func replaceUUID(tm *pgtype.Map) {
	t := &pgtype.Type{
		Name:  "uuid",
		OID:   pgtype.UUIDOID,
		Codec: uuidCodec{},
	}
	tm.RegisterType(t)
	tm.RegisterType(&pgtype.Type{
		Name:  "_uuid",
		OID:   pgtype.UUIDArrayOID,
		Codec: &pgtype.ArrayCodec{ElementType: t},
	})
}

// UuidCodec replaces [pgtype.UUIDCodec].
type uuidCodec struct{}

// DecodeDatabaseSQLValue implements [pgtype.Codec].
func (c uuidCodec) DecodeDatabaseSQLValue(m *pgtype.Map, oid uint32, format int16, src []byte) (driver.Value, error) {
	if src == nil {
		return nil, nil
	}
	var v uuid.UUID
	p := c.PlanScan(m, oid, format, &v)
	if p == nil {
		return nil, errors.New("todo")
	}
	if err := p.Scan(src, &v); err != nil {
		return nil, err
	}
	return v.String(), nil
}

// DecodeValue implements [pgtype.Codec].
func (c uuidCodec) DecodeValue(m *pgtype.Map, oid uint32, format int16, src []byte) (any, error) {
	if src == nil {
		return nil, nil
	}
	var v uuid.UUID
	p := c.PlanScan(m, oid, format, &v)
	if p == nil {
		return nil, errors.New("todo")
	}
	if err := p.Scan(src, &v); err != nil {
		return nil, err
	}
	return v[:], nil
}

// PlanEncode implements [pgtype.Codec].
func (uuidCodec) PlanEncode(_ *pgtype.Map, _ uint32, format int16, value any) pgtype.EncodePlan {
	if _, ok := value.(*uuid.UUID); ok {
		switch format {
		case pgtype.BinaryFormatCode:
			return encodePlanUUIDBinary{}
		case pgtype.TextFormatCode:
			return encodePlanUUIDText{}
		}
	}
	return nil
}

// PlanScan implements [pgtype.Codec].
func (uuidCodec) PlanScan(_ *pgtype.Map, _ uint32, format int16, target any) pgtype.ScanPlan {
	switch format {
	case pgtype.BinaryFormatCode:
		switch target.(type) {
		case *uuid.UUID:
			return scanPlanUUIDBinary{}
		}
	case pgtype.TextFormatCode:
		switch target.(type) {
		case *uuid.UUID:
			return scanPlanUUIDText{}
		}
	}
	return nil
}

// FormatSupported implements [pgtype.Codec].
func (uuidCodec) FormatSupported(f int16) bool {
	return f == pgtype.TextFormatCode || f == pgtype.BinaryFormatCode
}

// PreferredFormat implements [pgtype.Codec].
func (uuidCodec) PreferredFormat() int16 {
	return pgtype.BinaryFormatCode
}

// EncodePlanUUIDBinary implements [pgtype.EncodePlan] for the binary wire format.
type encodePlanUUIDBinary struct{}

// Encode implements [pgtype.EncodePlan].
func (encodePlanUUIDBinary) Encode(value any, buf []byte) (newBuf []byte, err error) {
	id := value.(*uuid.UUID)
	return append(buf, id[:]...), nil
}

// EncodePlanUUIDText implements [pgtype.EncodePlan] for the text wire format.
type encodePlanUUIDText struct{}

// Encode implements [pgtype.EncodePlan].
func (encodePlanUUIDText) Encode(value any, buf []byte) (newBuf []byte, err error) {
	id := value.(*uuid.UUID)
	b, err := id.MarshalText()
	if err != nil {
		return buf, err
	}
	return append(buf, b...), nil
}

// ScanPlanUUIDBinary implements [pgtype.ScanPlan] for the binary wire format.
type scanPlanUUIDBinary struct{}

// Scan implements [pgtype.ScanPlan].
func (scanPlanUUIDBinary) Scan(src []byte, target any) error {
	id := target.(*uuid.UUID)
	return id.UnmarshalBinary(src)
}

// ScanPlanUUIDText implements [pgtype.ScanPlan] for the text wire format.
type scanPlanUUIDText struct{}

// Scan implements [pgtype.ScanPlan].
func (scanPlanUUIDText) Scan(src []byte, target any) error {
	id := target.(*uuid.UUID)
	return id.UnmarshalText(src)
}
