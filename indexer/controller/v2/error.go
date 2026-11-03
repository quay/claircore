package controller

import (
	"errors"
	"fmt"
)

// Errors for the [Controller's] internal runloop.
var (
	// ErrGracePeriod is a signal that the step's grace period started and expired.
	errGracePeriod = errors.New("grace period exceeded")
	// ErrStepComplete is used to stop the per-step context.
	// This should not escape the step; it showing up outside the runloop means there's some wonky lifetimes.
	errStepComplete = errors.New("step complete")
)

type stepError struct {
	inner      error
	durability errorDurability
}

//go:generate go run golang.org/x/tools/cmd/stringer -type errorDurability -linecomment
type errorDurability uint

const (
	// ErrKindUnspecified is the default; the error says nothing about its durability.
	errKindUnspecified errorDurability = iota // unspecified
	// ErrKindBlob indicates there's some feature of the blob that means this step will never return a positive result.
	//
	// Typically there's something wrong with the blob, like it not actually being the expected kind of data.
	errKindBlob // blob
	// ErrKindCode indicates there's a bug in the code and retrying after a code change may yield a different result.
	errKindCode // code
	// ErrKindTransient indicates there was an environmental issue, retrying may yield a different result.
	errKindTransient // transient
)

func (e *stepError) Error() string {
	if e.durability == errKindUnspecified {
		return e.inner.Error()
	}
	return fmt.Sprintf("%v (durable for: %v)", e.inner, e.durability)
}
func (e *stepError) Unwrap() error {
	return e.inner
}

var errPerLayer = errors.New("per-layer error")

type layerError struct {
	layer, op string
	inner     error
}

// Error implements error.
func (e *layerError) Error() string {
	return fmt.Sprintf("%s for layer %s: %v", e.op, e.layer, e.inner)
}

func (e *layerError) Unwrap() error {
	return e.inner
}

func (e *layerError) Is(tgt error) bool {
	return errors.Is(errPerLayer, tgt)
}

func newLayerError(which string, op string, err error) error {
	return &layerError{
		layer: which,
		op:    op,
		inner: err,
	}
}
