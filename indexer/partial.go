package indexer

import (
	"errors"
	"fmt"
)

// ErrScanPartial indicates a scanner returned degraded but usable results.
var ErrScanPartial = errors.New("partial scan")

// PartialError wraps an error that should mark the containing index report as
// partial without failing the entire index operation.
type PartialError struct {
	Err error
}

func (e *PartialError) Error() string {
	if e == nil || e.Err == nil {
		return ErrScanPartial.Error()
	}
	return fmt.Sprintf("%s: %v", ErrScanPartial, e.Err)
}

func (e *PartialError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *PartialError) Is(target error) bool {
	return target == ErrScanPartial
}

// Partial wraps err as a partial scanner error.
func Partial(err error) error {
	if err == nil {
		return nil
	}
	return &PartialError{Err: err}
}
