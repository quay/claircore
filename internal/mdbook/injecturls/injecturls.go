// Package injecturls is an mdbook preprocessor meant to collect urls via a
// comment directive.
//
// Any string declaration with a directive like
//
//	//doc:url <keyword>
//
// Will get added to a list and slip-streamed into the documentation where
// there's a preprocessor directive like
//
//	{{# injecturls <keyword> }}
//
// Only go files are searched for directives. Any print verbs will be replaced with
// asterisks in the output.
package injecturls

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/claircore/internal/mdbook"
)

var (
	marker    = regexp.MustCompile(`\{\{#\s*injecturls\s(.+)\}\}`)
	printverb = regexp.MustCompile(`%[+#]*[a-z]`)
)

// Register registers the preprocessor.
func Register(_ context.Context, cfg *mdbook.Context, p *mdbook.Proc) error {
	chapter := func(_ context.Context, b *strings.Builder, c *mdbook.Chapter) error {
		if c.Path == nil {
			return nil
		}
		if !marker.MatchString(c.Content) {
			return nil
		}
		ms := marker.FindStringSubmatch(c.Content)
		if ct := len(ms); ct != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", ct)
		}
		keyword := strings.TrimSpace(ms[1])
		log.Println("injecting urls into:", *c.Path)
		var collect []string
		fn := walkFunc(inspectFunc(keyword, &collect))
		if err := filepath.WalkDir(cfg.Root, fn); err != nil {
			return err
		}

		for i, in := range collect {
			if i == 0 {
				b.WriteString("<ul>\n")
			}
			s, err := strconv.Unquote(in)
			if err != nil {
				return err
			}
			b.WriteString("<li>")
			b.WriteString(printverb.ReplaceAllLiteralString(s, `&ast;`))
			b.WriteString("</li>\n")
		}
		if b.Len() != 0 {
			b.WriteString("</ul>\n")
		}

		c.Content = marker.ReplaceAllLiteralString(c.Content, b.String())
		return nil
	}
	p.Chapter(chapter)
	return nil
}

func walkFunc(inspect func(ast.Node) bool) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, inspect)
		return nil
	}
}

func inspectFunc(keyword string, collect *[]string) func(ast.Node) bool {
	return func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || (decl.Tok != token.CONST && decl.Tok != token.VAR) {
			return true
		}
		collectblock := false
		if decl.Doc != nil {
			for _, c := range decl.Doc.List {
				if !strings.Contains(c.Text, "//doc:url") {
					continue
				}
				argv := strings.Fields(c.Text)
				if len(argv) != 2 {
					continue
				}
				if want, got := keyword, strings.TrimSpace(argv[1]); got != want {
					continue
				}
				collectblock = true
			}
		}
		for _, vs := range decl.Specs {
			v, ok := vs.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if !collectblock {
				if v.Doc == nil {
					continue
				}
				for _, c := range v.Doc.List {
					if !strings.Contains(c.Text, "//doc:url") {
						continue
					}
					argv := strings.Fields(c.Text)
					if len(argv) != 2 {
						continue
					}
					if want, got := keyword, strings.TrimSpace(argv[1]); got != want {
						continue
					}
					goto Collect
				}
				continue
			}
		Collect:
			for _, v := range v.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok {
					continue
				}
				if lit.Kind != token.STRING {
					continue
				}
				*collect = append(*collect, lit.Value)
			}
		}
		return true
	}
}
