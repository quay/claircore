package claircore

import (
	"errors"
	"strings"
)

// Error is the claircore error domain type.
//
// Errors coming from claircore components should be able to be inspected as
// ([errors.As]) an *Error at some point in the error chain.
//
// Implementers of claircore components should create an Error at the system
// boundary (e.g. when using a database client or reading a file) and
// intermediate layers should not wrap in another Error except to add additional
// [ErrorKind] information. That is to say, use [fmt.Errorf] with a "%w" verb in
// preference to creating a containing Error.
type Error struct {
	Inner   error
	Kind    ErrorKind
	Message string
	Op      string
}

// Assert this implements all the cool features.
var (
	_ error                       = (*Error)(nil)
	_ interface{ Is(error) bool } = (*Error)(nil)
	_ interface{ Unwrap() error } = (*Error)(nil)
)

// Error implements error.
func (e *Error) Error() string {
	var b strings.Builder
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(" ")
	}
	b.WriteString("[")
	switch e.Kind {
	case ErrConflict,
		ErrInternal,
		ErrInvalid,
		ErrPrecondition,
		ErrTransient:
		b.WriteString(string(e.Kind))
	default:
		b.WriteString("???")
	}
	b.WriteString("]: ")
	if e.Message != "" {
		b.WriteString(e.Message)
	}
	if e.Message != "" && e.Inner != nil {
		b.WriteString(": ")
	}
	if e.Op == "" && e.Message == "" {
		b.Reset()
	}
	if e.Inner != nil {
		b.WriteString(e.Inner.Error())
	}
	return b.String()
}

// Is enables [errors.Is].
//
// It compares the error kind. Callers should compare against a declared
// [ErrorKind] over a specific error.
func (e *Error) Is(kind error) bool {
	switch kind {
	case ErrVersionDependent:
		return !errors.Is(e, ErrTransient) && !errors.Is(e, ErrPermanent)
	default:
	}
	return errors.Is(e.Kind, kind)
}

// Unwrap enables [errors.Unwrap].
func (e *Error) Unwrap() error {
	return e.Inner
}

// ErrorKind represents classes of errors to be checked against.
//
// If an error is unsure which kind to use, ErrInternal should be used.
type ErrorKind string

// Defined error kinds.
var (
	ErrConflict     = ErrorKind("conflict")     // conflicting action
	ErrInternal     = ErrorKind("internal")     // non-specific internal error
	ErrInvalid      = ErrorKind("invalid")      // invalid request
	ErrPrecondition = ErrorKind("precondition") // some precondition unfulfilled
	ErrTransient    = ErrorKind("transient")    // may succeed on retry
	ErrPermanent    = ErrorKind("permanent")    // will never succeed

	// ErrVersionDependent should only be used for an [Is] comparison.
	// It's true for any error that's not marked as transient or permanent.
	ErrVersionDependent = ErrorKind("version dependent") // neither transient nor permanent, may not error in a future version

	// ErrPrecondition exists because ErrNotFound is claimed by the perfidious
	// Layer.Files method.
)

// Error implements error.
func (e ErrorKind) Error() string {
	return string(e)
}
