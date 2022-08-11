package controller

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/quay/claircore"
)

// ErrRetry is the sentinel error that errors can be tested against
// to see if they're retryable.
var errRetry = errors.New("retry")

// MarkRetryable does what it says on the tin.
func markRetryable(inner error) error {
	return &retryErr{inner: inner}
}

// RetryErr is the concrete type for a retryable error.
type retryErr struct {
	inner error
}

func (e *retryErr) Unwrap() error {
	return e.inner
}

func (e *retryErr) Is(tgt error) bool {
	return tgt == errRetry
}

func (e *retryErr) Error() string {
	return fmt.Sprintf("retryable: %v", e.inner)
}

// ManifestDisappearedErr is reported when a manifest disappeared since
// checking for its existence.
type manifestDisappearedErr struct {
	Digest claircore.Digest
}

func (e *manifestDisappearedErr) Error() string {
	return fmt.Sprintf("controller: manifest %q disappeared", e.Digest)
}

func (e *manifestDisappearedErr) Is(tgt error) bool {
	x, ok := tgt.(*manifestDisappearedErr)
	if !ok {
		return false
	}
	a, b := e.Digest, x.Digest
	return a.Algorithm() == b.Algorithm() && bytes.Equal(a.Checksum(), b.Checksum())
}

// ManifestDisappeared constructs an error to be reported when a manifest
// has disappeared.
func manifestDisappeared(d claircore.Digest) error {
	return &manifestDisappearedErr{
		Digest: d,
	}
}
