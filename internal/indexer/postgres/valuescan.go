package postgres

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/quay/claircore"
)

// this file implements any Valuer Scanner methods necessary to
// insert custom types into the postgres database.

// jsonbIndexReport is a type definition for claircore.IndexReport.
// we are able to cast a claircore.IndexReport to jsonbIndexReport
// and obtain the Value/Scan method set
type jsonbIndexReport claircore.IndexReport

func (sr jsonbIndexReport) Value() (driver.Value, error) {
	return json.Marshal(sr)
}

func (sr *jsonbIndexReport) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to type assert IndexReport to []bytes")
	}

	return json.Unmarshal(b, &sr)
}
