package test

import (
	"fmt"

	"github.com/quay/claircore"
)

// Some helpers for using gomock.

// DigestMatcher is a [gomock.Matcher] for [claircore.Digest]s.
type DigestMatcher string

// Matches implements [gomock.Matcher].
func (d *DigestMatcher) Matches(x any) bool {
	v := string(*d)
	switch x := x.(type) {
	case string:
		return v == x
	case *claircore.Digest:
		return v == x.String()
	default:
		if s, ok := x.(fmt.Stringer); ok {
			return v == s.String()
		}
	}
	return false
}

// String implements [gomock.Matcher].
func (d *DigestMatcher) String() string {
	return string(*d)
}

// LayerMatcher is a [gomock.Matcher] for [claircore.LayerDescription]s that
// allows them to match both [LayerDescription] and [Layer].
type LayerMatcher struct {
	*claircore.LayerDescription
}

// NewLayerMatcher returns a [LayerMatcher].
func NewLayerMatcher(desc *claircore.LayerDescription) *LayerMatcher {
	return &LayerMatcher{
		LayerDescription: desc,
	}
}

// DigestMatcher returns a [gomock.Matcher] implementation for the digest of the
// layer.
func (m *LayerMatcher) DigestMatcher() *DigestMatcher {
	return (*DigestMatcher)(&m.Digest)
}

// Matches implements [gomock.Matcher].
func (m *LayerMatcher) Matches(x any) bool {
	switch x := x.(type) {
	case *claircore.Layer:
		return x.Hash.String() == m.Digest
	case claircore.Layer:
		return x.Hash.String() == m.Digest
	case *claircore.LayerDescription:
		return x.Digest == m.Digest
	case claircore.LayerDescription:
		return x.Digest == m.Digest
	}
	return false
}

// String implements [gomock.Matcher].
func (m *LayerMatcher) String() string {
	return m.Digest
}
