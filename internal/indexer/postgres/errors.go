package postgres

import "fmt"

type dbError struct {
	inner error
	msg   string
	kind  errKind
}

func (e *dbError) Error() string {
	return fmt.Sprintf("postgres: %s: %v", e.msg, e.inner)
}

func (e *dbError) Unwrap() error {
	return e.inner
}

func (e *dbError) Is(t error) bool {
	switch e.kind {
	case errOther:
	case errIdempotent:
	case errRetryable:
	}
	return e == t
}

type errKind uint8

const (
	errOther errKind = iota
	errIdempotent
	errRetryable
)

func idempotent(msg string, err error) error {
	if err == nil {
		panic("programmer error")
	}
	return &dbError{
		inner: err,
		msg:   msg,
		kind:  errIdempotent,
	}
}
