// Package rpm allows for inspecting RPM databases in BerkleyDB, NDB, and SQLite
// formats.
package rpm

import (
	"context"
	"io"
	"iter"
)

const Version = "10"

// HeaderReader is the interface implemented for in-process RPM database handlers.
type HeaderReader interface {
	Headers(context.Context) iter.Seq2[io.ReaderAt, error]
}

// Validator is the extra interface an RPM database can implement if it needs
// extra checks after opening.
type validator interface {
	Validate(context.Context) error
}
