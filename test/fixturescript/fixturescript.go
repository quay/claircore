// Package fixturescript is a small language to declare claircore test fixtures.
//
// Fixture scripts are much easier to understand and modify than JSON or gob
// inputs, and allow for the serialization particulars of any type to be
// independent of the tests.
//
// # Language
// Each line of a script is parsed into a sequence of space-separated command
// words using shell quoting rules, with # marking an end-of-line comment.
//
// Exact semantics depend on the fixture being constructed, but generally
// commands are imperative: commands will affect commands that come after.
// The [CreateIndexReport] example demonstrates how it typically works.
//
// # Implementations
//
// The [Parse] function is generic, but requires specific conventions for the
// types passed in because dispatch happens via [reflect]. See the documentation
// of [Parse] and [Parser].
package fixturescript

import (
	"bufio"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/hugelgupf/go-shlex"
)

// Parse ...
func Parse[T any, Ctx any](out Parser[*T], pc *Ctx, name string, r io.Reader) (*T, error) {
	fv := reflect.ValueOf(out)
	// Do some reflect nastiness to make sure "fv" ends up with a pointer in it.
WalkType:
	switch fv.Kind() {
	case reflect.Pointer: // OK
	case reflect.Interface:
		fv = fv.Elem().Addr()
		goto WalkType
	default:
		fv = fv.Addr()
		goto WalkType
	}
	// We'll be passing this in to every call, so create it once.
	pcv := reflect.ValueOf(pc)
	// Use a static list of prefixes to use when constructing a call.
	// This allows for shorter names for more common cases.
	prefixes := []string{"", "Add", "Push", "Pop"}

	// TODO(hank) This function might be sped up by keeping a global cache for
	// this dispatcher construction, keyed by the "Parser" type.
	calls := make(map[string]reflect.Value)
	ft := fv.Type()
	for i := 0; i < ft.NumMethod(); i++ {
		m := ft.Method(i)
		// Disallow a command of the one method we statically know must be here.
		// It's not a real script environment, there's no way to manipulate the returned value.
		if m.Name == "Value" {
			continue
		}
		calls[m.Name] = m.Func
	}

	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line, _, _ := strings.Cut(s.Text(), "#")
		if len(line) == 0 {
			continue
		}

		var cmd string
		var args []string
		if i := strings.IndexFunc(line, unicode.IsSpace); i == -1 {
			cmd = line
		} else {
			cmd = line[:i]
			args = shlex.Split(line[i:])
		}

		// Slightly odd construction to try all the prefixes:
		// as soon as one name is valid, jump past the error return.
		var m reflect.Value
		var ok bool
		for _, pre := range prefixes {
			m, ok = calls[pre+cmd]
			if ok {
				goto Call
			}
		}
		return nil, fmt.Errorf("%s:%d: unrecognized command %q", name, lineNo, cmd)

	Call:
		av := reflect.ValueOf(args)
		// Next two lines will panic if not following the convention:
		res := m.Call([]reflect.Value{fv, pcv, av})
		if errRet := res[0]; !errRet.IsNil() {
			return nil, fmt.Errorf("%s:%d: command %s: %w", name, lineNo, cmd, errRet.Interface().(error))
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	return out.Value(), nil
}

// Parser ...
//
// There are additional restrictions on values used as a Parser:
//
//   - Any exported methods must have a pointer receiver.
//   - Exported methods must accept the "Ctx" type passed to [Parse] as the first argument,
//     a slice of strings as the second argument,
//     and return an [error].
type Parser[Out any] interface {
	Value() Out
}

// AssignToStruct is a helper for writing setter commands.
//
// It interprets the "args" array as a key-value pair separated by a "=".
// If the key is the name of a field, the value is interpreted as the type of
// the field and assigned to it. Supported types are:
//
//   - int64
//   - int
//   - string
//   - encoding.TextUnmarshaler
//   - json.Unmarshaler
func AssignToStruct[T any](tgt *T, args []string) (err error) {
	dv := reflect.ValueOf(tgt).Elem()
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("malformed arg: %q", arg)
		}
		f := dv.FieldByName(k)
		if !f.IsValid() {
			return fmt.Errorf("unknown key: %q", k)
		}
		switch x := f.Addr().Interface(); x := x.(type) {
		case *int64:
			*x, err = strconv.ParseInt(v, 10, 0)
		case *int:
			var tmp int64
			tmp, err = strconv.ParseInt(v, 10, 0)
			if err == nil {
				*x = int(tmp)
			}
		case *string:
			*x = v
		case encoding.TextUnmarshaler:
			err = x.UnmarshalText([]byte(v))
		case json.Unmarshaler:
			err = x.UnmarshalJSON([]byte(v))
		}
		if err != nil {
			return fmt.Errorf("key %q: bad value %q: %w", k, v, err)
		}
	}
	return nil
}
