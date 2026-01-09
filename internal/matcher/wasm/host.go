package wasm

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/quay/claircore"
)

// PtrMember is a helper to take a pointer to a Go struct, then return a
// pointer that's contained as a field.
func ptrMember(off uintptr) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		// Take in *A, which has a *B at offset "off".
		ref := unsafe.Pointer(api.DecodeExternref(stack[0])) // Shouldn't be nil.
		ptrField := unsafe.Add(ref, off)                     // This pointer can't be nil.
		ptr := *(*unsafe.Pointer)(ptrField)                  // Can be nil.
		stack[0] = api.EncodeExternref(uintptr(ptr))
	}
}

// PtrToMember is a helper to take a pointer to a Go struct, then return a
// pointer to a contained field.
func ptrToMember(off uintptr) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		// Take in *A, which has a B at offset "off".
		ref := unsafe.Pointer(api.DecodeExternref(stack[0])) // Shouldn't be nil.
		ptr := unsafe.Add(ref, off)                          // This pointer can't be nil.
		stack[0] = api.EncodeExternref(uintptr(ptr))
	}
}

// StringMember is a helper to take a pointer to a Go struct, then return a
// copy of a string member to a caller-allocated buffer.
func stringMember(off uintptr) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		// Unsure of another way to get this length information.
		h := (*reflect.StringHeader)(unsafe.Add(unsafe.Pointer(api.DecodeExternref(stack[0])), off))
		offset := api.DecodeU32(stack[1])
		lim := int(api.DecodeU32(stack[2]))
		s := unsafe.String((*byte)(unsafe.Pointer(h.Data)), h.Len)
		sz := min(lim, len(s))
		if sz == 0 {
			stack[0] = api.EncodeI32(0)
			return
		}
		s = s[:sz]
		mem := mod.ExportedMemory("memory")
		if mem.WriteString(offset, s) {
			stack[0] = api.EncodeI32(int32(sz))
		} else {
			stack[0] = api.EncodeI32(0)
		}
	}
}

// StringerMember is a helper to take a pointer to a Go struct, then place the
// string representation of a member into a caller-allocated buffer.
func stringerMember(off uintptr) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		iface := (any)(unsafe.Pointer(api.DecodeExternref(stack[0]) + off)).(fmt.Stringer)
		offset := api.DecodeU32(stack[1])
		lim := int(api.DecodeU32(stack[2]))
		s := iface.String()
		sz := min(lim, len(s))
		if mod.ExportedMemory("memory").WriteString(offset, s[:sz]) {
			stack[0] = api.EncodeI32(int32(sz))
		} else {
			stack[0] = api.EncodeI32(0)
		}
	}
}

// NotNil checks that the passed externref is not-nil.
//
// This is needed because externrefs are unobservable from within WASM; they
// can only be handed back to the host and not manipulated in any way.
func notNil(ctx context.Context, mod api.Module, stack []uint64) {
	if api.DecodeExternref(stack[0]) != 0 {
		stack[0] = api.EncodeI32(1)
	} else {
		stack[0] = api.EncodeI32(0)
	}
}

type methodSpec struct {
	Name        string
	Func        api.GoModuleFunc
	Params      []api.ValueType
	ParamNames  []string
	Results     []api.ValueType
	ResultNames []string
}

func (s *methodSpec) Build(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.NewFunctionBuilder().
		WithName(s.Name).
		WithParameterNames(s.ParamNames...).
		WithResultNames(s.ResultNames...).
		WithGoModuleFunction(s.Func, s.Params, s.Results).
		Export(s.Name)
}

func gettersFor[T any]() []methodSpec {
	t := reflect.TypeFor[T]()
	recv := strings.ToLower(t.Name())
	out := make([]methodSpec, 0, t.NumField())

	switch t {
	// These types are passed-in and always valid.
	case reflect.TypeFor[claircore.IndexRecord](),
		reflect.TypeFor[claircore.Vulnerability]():
	default:
		out = append(out, methodSpec{
			Name:        fmt.Sprintf("%s_valid", recv),
			Func:        notNil,
			Params:      []api.ValueType{api.ValueTypeExternref},
			Results:     []api.ValueType{api.ValueTypeI32},
			ParamNames:  []string{recv + "Ref"},
			ResultNames: []string{"ok"},
		})
	}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		if sf.Name == "ID" { // Skip "id" fields.
			continue
		}

		ft := sf.Type
		tgt := strings.ToLower(sf.Name)
		// Do some fixups:
		switch tgt {
		case "dist":
			tgt = "distribution"
		case "arch":
			tgt = "architecture"
		case "repo":
			tgt = "repository"
		}
		mi := len(out)
		out = append(out, methodSpec{})
		m := &out[mi]
		m.Name = fmt.Sprintf("%s_get_%s", recv, tgt)
		switch ft.Kind() {
		case reflect.Pointer:
			m.Func = ptrMember(sf.Offset)
			m.Params = []api.ValueType{api.ValueTypeExternref}
			m.Results = []api.ValueType{api.ValueTypeExternref}
			m.ParamNames = []string{recv + "Ref"}
			m.ResultNames = []string{tgt + "Ref"}
		case reflect.String:
			m.Func = stringMember(sf.Offset)
			m.Params = []api.ValueType{api.ValueTypeExternref, api.ValueTypeI32, api.ValueTypeI32}
			m.Results = []api.ValueType{api.ValueTypeI32}
			m.ParamNames = []string{recv + "Ref", "buf", "buf_len"}
			m.ResultNames = []string{"len"}
		case reflect.Struct:
			switch {
			case ft == reflect.TypeFor[claircore.Version]():
				m.Func = ptrToMember(sf.Offset)
				m.Params = []api.ValueType{api.ValueTypeExternref}
				m.Results = []api.ValueType{api.ValueTypeExternref}
				m.ParamNames = []string{recv + "Ref"}
				m.ResultNames = []string{tgt + "Ref"}
			case ft.Implements(reflect.TypeFor[fmt.Stringer]()):
				m.Func = stringerMember(sf.Offset)
				m.Params = []api.ValueType{api.ValueTypeExternref, api.ValueTypeI32, api.ValueTypeI32}
				m.Results = []api.ValueType{api.ValueTypeI32}
				m.ParamNames = []string{recv + "Ref", "buf", "buf_len"}
				m.ResultNames = []string{"len"}
			default:
				out = out[:mi]
			}
		default:
			out = out[:mi]
		}
	}

	return slices.Clip(out)
}

var hostV1Interface = sync.OnceValue(func() []methodSpec {
	return slices.Concat(
		gettersFor[claircore.IndexRecord](),
		gettersFor[claircore.Detector](),
		gettersFor[claircore.Distribution](),
		gettersFor[claircore.Package](),
		gettersFor[claircore.Range](),
		gettersFor[claircore.Repository](),
		gettersFor[claircore.Version](),
		gettersFor[claircore.Vulnerability](),
	)
})

func buildHostV1Interface(rt wazero.Runtime) wazero.HostModuleBuilder {
	b := rt.NewHostModuleBuilder("claircore_matcher_1")
	for _, spec := range hostV1Interface() {
		b = spec.Build(b)
	}
	return b
}
