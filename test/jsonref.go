package test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"testing"
)

// Hard-coded toggle for test-debugging output. Only useful for debugging the
// JSONRef implementation.
const jsonRefDebug = false

// LoadJSON unmarshals "data" into a type T, resolving file references from
// "sys".
func loadJSON[T any](t testing.TB, sys fs.FS, data []byte) (*T, error) {
	t.Helper()

	inter := make(map[string]any)
	if err := json.Unmarshal(data, &inter); err != nil {
		return nil, err
	}
	loadRef := resolveRef(t, sys)

	var walk func(string, any)
	walk = func(p string, v any) {
		if jsonRefDebug {
			t.Logf("walk: %s (%T)", p, v)
		}
		switch obj := v.(type) {
		case map[string]any:
			for k, v := range obj {
				p := fmt.Sprintf("%s.%s", p, k)
				if tgt, ok := v.(map[string]any); ok && isRef(tgt) {
					obj[k] = loadRef(p, tgt[`$ref`].(string))
				}
				walk(p, obj[k])
			}
		case []any:
			for i, v := range obj {
				p := fmt.Sprintf("%s.%d", p, i)
				if tgt, ok := v.(map[string]any); ok && isRef(tgt) {
					obj[i] = loadRef(p, tgt[`$ref`].(string))
				}
				walk(p, obj[i])
			}
		}
	}
	walk("$", inter)

	b, err := json.Marshal(inter)
	if err != nil {
		return nil, err
	}
	v := new(T)
	if err := json.Unmarshal(b, v); err != nil {
		return nil, err
	}
	return v, nil
}

// ResolveRef closes over the passed arguments and returns a function loading
// JSON from "ref", using the JSONPath "at" for logging and error reporting.
func resolveRef(t testing.TB, sys fs.FS) func(at string, ref string) any {
	return func(at string, ref string) (repl any) {
		if jsonRefDebug {
			t.Logf("load ref at %s", at)
		}
		u, err := url.Parse(ref)
		if err != nil {
			t.Errorf("ref@%s(%s): %v", at, ref, err)
			return nil
		}
		if u.Scheme != "file" {
			t.Errorf(`ref@%s(%s): only "file" schemes supported (got %q)`, at, ref, u.Scheme)
			return nil
		}
		if !fs.ValidPath(u.Opaque) {
			t.Errorf(`ref@%s(%s):only relative path supported (got %q)`, at, ref, u.Opaque)
			return nil
		}
		data, err := fs.ReadFile(sys, u.Opaque)
		if err != nil {
			t.Errorf("loading %q: %v", u.String(), err)
			return nil
		}
		if jsonRefDebug {
			t.Logf("loading %q: got %d bytes", u.String(), len(data))
		}
		if err := json.Unmarshal(data, &repl); err != nil {
			t.Errorf("loading %q: %v", u.String(), err)
			return nil
		}
		if repl == nil {
			t.Errorf("loading %q: loaded nil??", u.String())
		}
		return repl
	}
}

// IsRef reports if the object is a JsonRef.
func isRef(v map[string]any) bool {
	tgt, ok := v[`$ref`]
	if !ok {
		return false
	}
	_, typOK := tgt.(string)
	return typOK
}
