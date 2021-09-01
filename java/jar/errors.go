package jar

import (
	"errors"
	"fmt"
)

// LocalError is a type for errors returned from this package.
type localError struct {
	inner error
	msg   string
}

// These are sentinel errors that can be used with errors.Is.
var (
	ErrUnidentified = errors.New("unidentified jar")
	ErrNotAJar      = errors.New("does not seem to be a jar")
)

func (e *localError) Error() string {
	switch {
	case e.inner == nil && e.msg == "":
		panic("programmer error")
	case e.inner == nil && e.msg != "":
		return "jar: " + e.msg
	case e.inner != nil && e.msg == "":
		return fmt.Sprintf("jar: %v", e.inner)
	case e.inner != nil && e.msg != "":
		return fmt.Sprintf("jar: %s: %v", e.msg, e.inner)
	}
	panic("unreachable")
}

func (e *localError) Unwrap() error {
	return e.inner
}

func mkErr(msg string, err error) *localError {
	return &localError{msg: msg, inner: err}
}

type errUnidentified struct {
	name string
}

func unidentified(n string) *errUnidentified {
	return &errUnidentified{n}
}

func (e *errUnidentified) Is(target error) bool {
	return target == ErrUnidentified || target == e
}

func (e *errUnidentified) Error() string {
	return fmt.Sprintf("unidentified jar: %s", e.name)
}

type errNotAJar struct {
	inner error
	name  string
}

func notAJar(name string, reason error) *errNotAJar {
	return &errNotAJar{name: name, inner: reason}
}

func (e *errNotAJar) Error() string {
	return fmt.Sprintf("%q not a jar: %v", e.name, e.inner)
}

func (e *errNotAJar) Unwrap() error {
	return e.inner
}

func (e *errNotAJar) Is(target error) bool {
	return target == ErrNotAJar || target == e
}
