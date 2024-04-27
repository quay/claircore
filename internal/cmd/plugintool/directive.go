package main

import (
	"go/ast"
	"go/token"
	"path"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Prefix is the prefix looked for in Go comments.
const Prefix = `//plugintool:`

// Directives returns all the discovered directives in the specified module.
func Directives(mod string) ([]Package, error) {
	cfg := packages.Config{
		Mode: packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedEmbedFiles | packages.NeedName,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(&cfg, path.Join(mod, "..."))
	if err != nil {
		return nil, err
	}
	var out []Package

	for _, pkg := range pkgs {
		var found []Directive
		pkg.Fset = cfg.Fset // Feels bad, but much easier to pass along the FileSet.
		for _, f := range pkg.Syntax {
			cm := ast.NewCommentMap(cfg.Fset, f, f.Comments)
			for n, groups := range cm {
				for _, group := range groups {
					if group.Pos() < f.Package {
						continue
					}
					for _, c := range group.List {
						if !strings.HasPrefix(c.Text, Prefix) {
							continue
						}
						found = append(found, Directive{
							Node: n,
							Args: strings.Fields(strings.TrimPrefix(c.Text, Prefix)),
						})
					}
				}
			}
		}
		if len(found) != 0 {
			out = append(out, Package{
				Package:   pkg,
				Directive: found,
			})
		}
	}

	return out, nil
}

// Package is a Go package with discovered directives.
type Package struct {
	*packages.Package
	Directive []Directive
}

// Directive is the discovered directive and the associated AST node.
type Directive struct {
	Node ast.Node
	Args []string
}

// IdentExists returns a function suitable for using with [ast.Inspect] that
// will assign the [*ast.GenDecl] for the name "id" to "out", if found.
func IdentExists(out **ast.GenDecl, id string) func(ast.Node) bool {
	return func(n ast.Node) bool {
		if *out != nil {
			return false
		}
		switch g := n.(type) {
		case *ast.File:
			return true
		case *ast.GenDecl:
			if g.Tok == token.IMPORT || g.Tok == token.TYPE {
				return false
			}
			for _, s := range g.Specs {
				v, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, n := range v.Names {
					if n.String() == id {
						*out = g
						break
					}
				}
			}
		}
		return false
	}
}
