package main

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"
)

// RunCodegen is the entrypoint for the codegen mode.
func runCodegen(ctx context.Context, mod, scope string, packageName *string) (io.Reader, error) {
	if packageName == nil {
		n, err := guessName()
		if err != nil {
			return nil, err
		}
		packageName = &n
	}

	pkgs, err := Directives(mod)
	if err != nil {
		return nil, err
	}

	var items []GenItem
	var buf bytes.Buffer
	for _, pkg := range pkgs {
		for _, d := range pkg.Directive {
			var i GenItem
			switch {
			case len(d.Args) < 2:
				// Unknown form, skip.
			case len(d.Args) > 3:
				// Unknown form, skip.
			case d.Args[0] != "register":
				continue // Not for us, skip.
			case d.Args[1] != scope:
				continue // Not for us, skip.
			case len(d.Args) == 3:
				n := strconv.Quote(d.Args[2])
				i.LiteralName = &n
			}
			i.Package = pkg.PkgPath
			var spec *ast.ValueSpec
			switch x := d.Node.(type) {
			case *ast.GenDecl:
				spec = x.Specs[0].(*ast.ValueSpec)
			case *ast.ValueSpec:
				spec = x
			default:
				return nil, fmt.Errorf("directive found associated with unexpected type: %T (%v)", x, pkg.Fset.Position(x.Pos()))
			}
			i.Description = spec.Names[0].Name
			val := spec.Values[0].(*ast.CompositeLit)
			switch idx := val.Type.(*ast.IndexExpr).Index.(type) {
			case *ast.Ident:
				// This branch handles the case where a Description is in the "scope" package.
				// It rewrites the index expression to be fully qualified.
				val.Type.(*ast.IndexExpr).Index = &ast.SelectorExpr{
					X:   ast.NewIdent(path.Base(scope)),
					Sel: idx,
				}
			case *ast.SelectorExpr: // OK
			default:
				return nil, fmt.Errorf("directive found associated with unexpected type: %T (%v)", val, pkg.Fset.Position(val.Pos()))
			}
			buf.Reset()
			printer.Fprint(&buf, pkg.Fset, val.Type)
			i.Type = buf.String()
			if i.LiteralName == nil {
				guess := strings.TrimSuffix(spec.Names[0].Name, "Description") + "Name"
				var decl *ast.GenDecl
				for _, f := range pkg.Syntax {
					ast.Inspect(f, IdentExists(&decl, guess))
					if decl != nil {
						break
					}
				}
				if decl == nil {
					return nil, fmt.Errorf("in %q: unable to find expected ident %q", pkg.PkgPath, guess)
				}
				switch decl.Tok {
				case token.VAR: // OK, linkname will work fine.
					i.Name = &guess
				case token.CONST:
					// Need to copy the const.
					spec := decl.Specs[0].(*ast.ValueSpec)
					lit := spec.Values[0].(*ast.BasicLit)
					i.LiteralName = &lit.Value
				default:
					return nil, fmt.Errorf("directive found associated with unexpected type: %T (%v)", decl, pkg.Fset.Position(decl.Pos()))
				}
			}
			items = append(items, i)
		}
	}

	buf.Reset()
	if err := tmpl.Execute(&buf, &TemplateContext{
		Name:  *packageName,
		Scope: scope,
		Items: items,
	}); err != nil {
		return nil, err
	}
	b, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

// GuessName reports the first name for the package in the current directory
// that isn't a main or test package.
func guessName() (string, error) {
	set := token.NewFileSet()
	ps, err := parser.ParseDir(set, ".", nil, 0)
	if err != nil {
		return "", err
	}
	for name := range ps {
		switch {
		case name == "main": // skip
		case strings.HasSuffix(name, "_test"): // skip
		default:
			return name, nil
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return "", fmt.Errorf("unable to guess package name in %q", wd)
}

// GenItem is an individual codegen item.
type GenItem struct {
	Package     string
	Description string
	Type        string
	// Only one of "Name" or "LiteralName" should be populated.
	Name        *string // Identifier in remote package that contains the name.
	LiteralName *string // Formatted literal of the name, copied out of the comment or source.
}

// San sanitizes Go identifiers.
var san = strings.NewReplacer("/", "_", ".", "_")

// LocalDesc returns a local name for the Description.
func (i *GenItem) localDesc() string {
	return san.Replace(path.Join(i.Package, i.Description))
}

// LocalName returns a local name for a value holding the plugin name.
func (i *GenItem) localName() string {
	return san.Replace(path.Join(i.Package, *i.Name))
}

// Vars returns a [fmt.Formatter] that emits var/const declarations for the
// local file.
func (i *GenItem) Vars() fmt.Formatter {
	return (*VarFormatter)(i)
}

// Register returns a [fmt.Formatter] that emits [registry.Register] calls for
// the local file.
func (i *GenItem) Register() fmt.Formatter {
	return (*RegFormatter)(i)
}

// VarFormatter is a [fmt.Formatter] that emits needed var/const declarations.
type VarFormatter GenItem

// Format implements [fmt.Formatter].
func (v *VarFormatter) Format(f fmt.State, _ rune) {
	i := (*GenItem)(v)
	d := i.localDesc()
	fmt.Fprintf(f, "//go:linkname %s %s.%s\n", d, i.Package, i.Description)
	fmt.Fprintf(f, "var %s %s\n", d, i.Type)
	if i.Name == nil {
		return
	}
	n := i.localName()
	fmt.Fprintf(f, "//go:linkname %s %s.%s\n", n, i.Package, *i.Name)
	fmt.Fprintf(f, "var %s string\n", n)
}

// RegFormatter is a [fmt.Formatter] that emits needed [registry.Register] calls.
type RegFormatter GenItem

// Format implements [fmt.Formatter].
func (v *RegFormatter) Format(f fmt.State, _ rune) {
	i := (*GenItem)(v)
	fmt.Fprintln(f, `if err := registry.Register(`)
	if i.LiteralName != nil {
		fmt.Fprint(f, *i.LiteralName)
	} else {
		fmt.Fprint(f, i.localName())
	}
	fmt.Fprint(f, ",\n")
	fmt.Fprint(f, "&")
	fmt.Fprint(f, i.localDesc())
	fmt.Fprint(f, ",\n")
	fmt.Fprintln(f, "); err != nil {")
	fmt.Fprintln(f, "errs = append(errs, err)")
	fmt.Fprintln(f, "}")
}

// TemplateContext is the data expected to be passed to executions of [tmpl].
type TemplateContext struct {
	Name  string
	Scope string
	Items []GenItem
}

// Tmpl is the codegen template.
var tmpl = template.Must(template.New("root").Parse(`// Code generated by internal/cmd/plugintool; DO NOT EDIT.

package {{.Name}}

import "errors"
import _ "unsafe" // Needed for linker tricks
import "github.com/quay/claircore/toolkit/registry"
import "github.com/quay/claircore/{{.Scope}}"

{{ range .Items }}{{ .Vars }}
{{- end }}

func init() {
	var errs []error
{{ range .Items }}{{ .Register }}
{{- end }}
	if len(errs) != 0 {
		panic(errors.Join(errs...))
	}
}
`))
