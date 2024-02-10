package dockerfile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
	"rsc.io/script"
	"rsc.io/script/scripttest"
)

func TestGetLabels(t *testing.T) {
	ctx := context.Background()
	e := script.NewEngine()
	e.Cmds = scripttest.DefaultCmds()
	e.Conds = scripttest.DefaultConds()
	e.Cmds["GetLabels"] = CmdGetLabels
	const defaultScript = `# Check for expected JSON output.
GetLabels
cmp Got Want
`

	ms, err := filepath.Glob("testdata/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		t.Run(strings.TrimSuffix(filepath.Base(m), filepath.Ext(m)), func(t *testing.T) {
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatalf("error parsing %q: %v", m, err)
			}
			wd := t.TempDir()
			s, err := script.NewState(ctx, wd, nil)
			if err != nil {
				t.Fatalf("error constructing *State: %v", err)
			}
			if err := s.ExtractFiles(ar); err != nil {
				t.Fatalf("error with ExtractFiles: %v", err)
			}
			log := new(strings.Builder)
			defer func() {
				if err := s.CloseAndWait(log); err != nil {
					t.Error(err)
				}
				if log.Len() > 0 {
					t.Log(strings.TrimSuffix(log.String(), "\n"))
				}
			}()
			sr := bytes.NewBuffer(ar.Comment)
			if sr.Len() == 0 {
				m = "(default script)"
				sr = bytes.NewBufferString(defaultScript)
			}
			if err := e.Execute(s, m, bufio.NewReader(sr), log); err != nil {
				t.Error(err)
			}
		})
	}
}

var CmdGetLabels = script.Command(
	script.CmdUsage{
		Summary: "parse a Dockerfile and return the labels of the named files",
		Args:    "[input]",
		Detail: []string{
			"If a filename is not given, 'Dockerfile' is assumed.",
			"The result is JSON-encoded with indents of two spaces and written to the file 'Got'.",
			"If there's an error, it is printed to stderr.",
		},
	},
	func(s *script.State, args ...string) (script.WaitFunc, error) {
		name := "Dockerfile"
		switch len(args) {
		case 0:
		case 1:
			name = args[0]
		default:
			return nil, errors.New("bad number of arguments: want at most 1")
		}

		in, err := os.Open(filepath.Join(s.Getwd(), name))
		if err != nil {
			return nil, err
		}
		out, err := os.Create(filepath.Join(s.Getwd(), "Got"))
		if err != nil {
			in.Close()
			return nil, err
		}
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")

		return func(s *script.State) (stdout, stderr string, err error) {
			defer in.Close()
			defer out.Close()
			var got map[string]string
			got, err = GetLabels(s.Context(), in)
			if err == nil {
				if encErr := enc.Encode(got); encErr != nil {
					err = fmt.Errorf("json error: %w", encErr)
				}
			} else {
				stderr = err.Error() + "\n"
				err = errors.New("GetLabels failed")
			}
			return
		}, nil
	},
)

func TestSplit(t *testing.T) {
	for _, p := range []struct {
		In   string
		Want []string
	}{
		{
			In:   "",
			Want: nil,
		},
		{
			In:   "k=v",
			Want: []string{"k=v"},
		},
		{
			In:   `k=v\ v`,
			Want: []string{`k=v\ v`},
		},
		{
			In:   `k=v k=v k=v`,
			Want: []string{`k=v`, `k=v`, `k=v`},
		},
		{
			In:   `k=" v "`,
			Want: []string{`k=" v "`},
		},
		{
			In:   `k=' v '`,
			Want: []string{`k=' v '`},
		},
		{
			In:   `k=' v ' k="   "`,
			Want: []string{`k=' v '`, `k="   "`},
		},
		{
			In:   "k=' v '	\v k=\"   \"",
			Want: []string{`k=' v '`, `k="   "`},
		},
		{
			In:   "k=' v ' \t\"k\"=\"   \"",
			Want: []string{`k=' v '`, `"k"="   "`},
		},
	} {
		t.Logf("input: %#q", p.In)
		got, err := splitKV('\\', p.In)
		if err != nil {
			t.Error(err)
		}
		if want := p.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
