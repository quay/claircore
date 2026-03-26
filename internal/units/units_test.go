package units

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestUnits ensures that top-level variables in "units.go" declared with
// [metric.ByUnit] are valid UCUM units.
func TestUnits(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "units.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	stack := make([]ast.Node, 0, 1)
	units := loadUnits(t)
	ast.PreorderStack(f, stack, func(n ast.Node, _ []ast.Node) (descend bool) {
		if _, ok := n.(*ast.File); ok {
			return true
		}
		decl, ok := n.(*ast.GenDecl)
		if !ok {
			return
		}
		if decl.Tok != token.VAR {
			return
		}
		for _, spec := range decl.Specs {
			spec := spec.(*ast.ValueSpec)
			if spec.Type != nil {
				continue
			}
			for i, name := range spec.Names {
				if !name.IsExported() {
					continue
				}
				v := spec.Values[i]
				c, ok := v.(*ast.CallExpr)
				if !ok || len(c.Args) != 1 {
					continue
				}
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok || sel.X.(*ast.Ident).Name != "metric" || sel.Sel.Name != "WithUnit" {
					continue
				}
				lit, ok := c.Args[0].(*ast.BasicLit)
				if !ok {
					continue
				}
				u, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Errorf("%v: %v", fset.Position(spec.Pos()), err)
					continue
				}
				if _, ok := units[u]; !ok {
					t.Errorf("%s:\tunknown unit %q @ %v", name.Name, u, fset.Position(spec.Pos()))
				} else {
					t.Logf("%s:\tknown unit %q", name.Name, u)
				}
			}
		}
		return
	})
}

func loadUnits(t testing.TB) map[string]struct{} {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", "ucum-cs.units"))
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(f)
	defer func() {
		if err := s.Err(); err != nil {
			t.Errorf("scanner error: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

	seq := func(yield func(string, struct{}) bool) {
		for s.Scan() {
			l, _, _ := strings.Cut(s.Text(), "#")
			fs := strings.Fields(l)
			switch {
			case len(fs) == 2 && fs[0] == "base":
				l = fs[1]
			case len(fs) == 5 && fs[4] == "metric":
				l = fs[0]
			default:
				continue
			}

			if !yield(l, struct{}{}) {
				return
			}
		}
	}

	return maps.Collect(seq)
}
