package postgres

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/quay/claircore"
)

// this file implements any Valuer Scanner methods necessary to
// insert custom types into the postgres database.

// jsonbScanReport is a type definition for scanner.ScanReport.
// we are able to cast a scanner.ScanReport to jsonbScanReport
// and obtain the Value/Scan method set
type jsonbScanReport claircore.ScanReport

func (sr jsonbScanReport) Value() (driver.Value, error) {
	return json.Marshal(sr)
}

func (sr *jsonbScanReport) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to type assert ScanReport to []bytes")
	}

	return json.Unmarshal(b, &sr)
}
