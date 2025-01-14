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

// ErrNotAJar is a sentinel error that can be used with errors.Is.
var ErrNotAJar = errors.New("does not seem to be a jar")

func (e *localError) Error() string {
	switch {
	case e.inner == nil && e.msg == "":
		panic("programmer error: no error or message")
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
func archiveErr(m srcPath, err error) *localError {
	return &localError{
		msg:   fmt.Sprintf("at %q", m.String()),
		inner: err,
	}
}

type errNotAJar struct {
	inner error
	name  string
}

func notAJar(p srcPath, reason error) *errNotAJar {
	return &errNotAJar{name: p.String(), inner: reason}
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
