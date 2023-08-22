//go:build ignore

// Injecturls is a helper meant to collect urls via a comment directive.
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
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"os/signal"
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("injecturls: ")
	mdbook.Args(os.Args)

	cfg, book, err := mdbook.Decode(os.Stdin)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	proc := mdbook.Proc{
		Chapter: func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
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
			inspectFunc := func(n ast.Node) bool {
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
						collect = append(collect, lit.Value)
					}
				}
				return true
			}
			walkFunc := func(p string, d fs.DirEntry, err error) error {
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
				ast.Inspect(f, inspectFunc)
				return nil
			}
			if err := filepath.WalkDir(cfg.Root, walkFunc); err != nil {
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
		},
	}
	if err := proc.Walk(ctx, book); err != nil {
		panic(err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
		panic(err)
	}
}
