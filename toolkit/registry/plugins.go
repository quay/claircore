// Package registry is the central registry for all pluggable components in
// Claircore.
//
// Code referring to a pluggable component should use the name across API
// boundaries instead of passing instances of the objects.
package registry

import (
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/quay/claircore/toolkit/urn"
)

// Registry is the global registry.
var registry = struct {
	sync.RWMutex
	Lookup map[reflect.Type]interface{}
}{
	Lookup: make(map[reflect.Type]interface{}),
}

// TypedReg is the per-type registry.
type typedReg[T any] struct {
	sync.RWMutex
	Lookup   map[string]*Description[T]
	AsPassed map[string]string
}

// GetNames returns the names for which the passed function reports true.
func (r *typedReg[T]) getNames(f func(*Description[T]) bool) []string {
	r.RLock()
	defer r.RUnlock()
	ret := make([]string, 0, len(r.Lookup))
	for n, d := range r.Lookup {
		if f(d) {
			ret = append(ret, r.AsPassed[n])
		}
	}
	sort.Strings(ret)
	return ret
}

// GetReg does the type assertion from the global registry to the per-type
// registry. The returned cleanup function should be called unconditionally. The
// returned *typedReg may be nil if the "create" argument is false.
func getReg[T any](create bool) (*typedReg[T], func()) {
	key := reflect.TypeOf((*T)(nil)).Elem()
	registry.RLock()
	v, ok := registry.Lookup[key]
	if !ok {
		registry.RUnlock()
		if !create {
			return nil, func() {}
		}
		registry.Lock()
		v2, ok := registry.Lookup[key]
		if ok {
			v = v2
		} else {
			v = &typedReg[T]{
				Lookup:   make(map[string]*Description[T]),
				AsPassed: make(map[string]string),
			}
			registry.Lookup[key] = v
		}
		registry.Unlock()
		registry.RLock()
	}
	reg := v.(*typedReg[T]) // Don't check the assertion, panic on purpose.
	return reg, registry.RUnlock
}

// Default reports the names of the plugins that are default-enabled for the
// given type parameter.
func Default[T any]() []string {
	tr, unlock := getReg[T](false)
	defer unlock()
	if tr == nil {
		return nil
	}
	return tr.getNames(func(d *Description[T]) bool { return d.Default })
}

// All reports the names of the plugins that are registered for the given type
// parameter.
func All[T any]() []string {
	tr, unlock := getReg[T](false)
	defer unlock()
	if tr == nil {
		return nil
	}
	return tr.getNames(func(_ *Description[T]) bool { return true })
}

// Description is a description of all the information and hooks to construct a
// plugin of type T.
type Description[T any] struct {
	_ noCopy
	// JSON Schema to validate a configuration against.
	// See https://json-schema.org/ for information on the format.
	ConfigSchema string
	// New is a constructor for the given type.
	//
	// The passed function will unmarshal a configuration into the provided
	// value. JSON is the default format, unless a Capability flag indicates
	// otherwise.
	New func(context.Context, func(any) error) (T, error)
	// Capabilities flags.
	//
	// Meanings are set per-type.
	Capabilities uint
	// Default signals that the plugin should be enabled by default.
	Default bool
}

var (
	// ErrAlreadyRegistered is returned when a name is attempted to be registered
	// more than once.
	ErrAlreadyRegistered = errors.New("registry: name already registered")
	// ErrBadName is returned when a name is malformed.
	ErrBadName = errors.New("registry: bad name")
)

// Register registers the provided description with the provided name in the
// type-specific registry indicated by the type parameter.
//
// Register may report errors if the name is already in use, or if the provided
// name is not valid.
func Register[T any](name string, desc *Description[T]) error {
	u, err := urn.Parse(name)
	if err != nil {
		return errName(name, err)
	}
	n, err := u.Name()
	if err != nil {
		return errName(name, err)
	}
	if err := checkname[T](&n); err != nil {
		return errName(name, err)
	}
	key := u.Normalized()

	tr, unlock := getReg[T](true)
	defer unlock()
	tr.Lock()
	defer tr.Unlock()
	if _, exists := tr.Lookup[key]; exists {
		return errRegistered(name)
	}
	tr.Lookup[key] = desc
	tr.AsPassed[key] = name
	return nil
}

type regErr struct {
	name  string
	inner error
}

func errName(name string, err error) error {
	return &regErr{name: name, inner: err}
}
func errRegistered(name string) error {
	return &regErr{name: name, inner: ErrAlreadyRegistered}
}

func (e *regErr) Error() string {
	if e.inner == ErrAlreadyRegistered {
		return fmt.Sprintf("registry: name already registered: %q", e.name)
	}
	return fmt.Sprintf("registry: bad name %q: %v", e.name, e.inner)
}
func (e *regErr) Is(tgt error) bool {
	return e.inner != ErrAlreadyRegistered && tgt == ErrBadName
}
func (e *regErr) Unwrap() error {
	return e.inner
}

// GetDescription returns Descriptions identified by the names in the registry
// indicated by the type parameter.
//
// An error will be reported if an unknown name is provided or if the type
// parameter has no names registered for it.
func GetDescription[T any](names ...string) (map[string]*Description[T], error) {
	keys := make([]string, len(names))
	for i, n := range names {
		u, err := urn.Parse(n)
		if err != nil {
			return nil, fmt.Errorf("registry: bad name at parameter %d: %w", i, err)
		}
		n, err := u.Name()
		if err != nil {
			return nil, fmt.Errorf("registry: bad name at parameter %d: %w", i, err)
		}
		if err := checkname[T](&n); err != nil {
			return nil, fmt.Errorf("registry: bad name at parameter %d: %w", i, err)
		}
		keys[i] = u.Normalized()
	}
	tr, unlock := getReg[T](false)
	defer unlock()
	if tr == nil {
		var t T
		return nil, fmt.Errorf("registry: unknown type: %T", t)
	}
	tr.RLock()
	defer tr.RUnlock()
	ret := make(map[string]*Description[T], len(names))
	for _, k := range keys {
		d, ok := tr.Lookup[k]
		if !ok {
			var t T
			return nil, fmt.Errorf("registry: type %T: unknown name: %q", t, k)
		}
		ret[k] = d
	}
	return ret, nil
}

// Checkname makes sure the passed name is congruent with the expected type.
func checkname[T any](n *urn.Name) error {
	var t *T
	typ := reflect.TypeOf(t).Elem()
	tk := strings.ToLower(typ.Name())
	ts := strings.ToLower(path.Base(typ.PkgPath()))
	switch {
	case n.System != ts:
		return fmt.Errorf("expected %q for system component, got %q", ts, n.System)
	case n.Kind != tk:
		return fmt.Errorf("expected %q for kind component, got %q", tk, n.Kind)
	default:
		// OK
	}
	return nil
}

// NoCopy is a trick to get `go vet` to complain about accidental copying.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
