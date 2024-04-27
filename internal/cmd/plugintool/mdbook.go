package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/doc/comment"
	"go/token"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/quay/claircore/internal/mdbook"
	"github.com/quay/claircore/internal/plugin"

	"github.com/quay/claircore/toolkit/urn"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"golang.org/x/tools/go/packages"
)

// RunMdbook is the entrypoint for mdBook mode.
//
// BUG(hank) doc postprocessing unimplemented
func runMdbook(ctx context.Context, root string) error {
	marker := regexp.MustCompile(`\{\{#\s*plugintool\s+(\w+)\s*(\w+)?\}\}`)
	argv := append([]string{""}, flag.Args()...)
	mdbook.Args(argv)
	cfg, book, err := mdbook.Decode(os.Stdin)
	if err != nil {
		return err
	}
	_ = cfg

	var docErr error
	var docOnce sync.Once

	proc := mdbook.Proc{
		Chapter: func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
			if c.Path == nil {
				return nil
			}
			if !marker.MatchString(c.Content) {
				return nil
			}
			var docs docMap
			var err error
			docOnce.Do(func() {
				docs, err = docSetup()
			})
			if docErr != nil {
				return docErr
			}
			ms := marker.FindStringSubmatch(c.Content)
			var scope, pat string
			switch len(ms) {
			case 3:
				pat = ms[2]
				fallthrough
			case 2:
				scope = ms[1]
			default:
				return fmt.Errorf("unexpected number of arguments: %d", len(ms))
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return err
			}
			cmd, ok := docs["register"]
			if !ok {
				return nil
			}
			ps, ok := cmd[scope]
			if !ok {
				return nil
			}
			var names []string
			for n := range ps {
				if re.MatchString(n) {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			var buf bytes.Buffer
			for _, n := range names {
				if err := ps[n].Render(&buf, n); err != nil {
					return err
				}
			}
			c.Content = marker.ReplaceAllLiteralString(c.Content, buf.String())
			return nil
		},
	}
	if err := proc.Walk(ctx, book); err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(&book)
}

// command -> scope -> name -> Docs
type docMap = map[string]map[string]map[string]*Doc

type Doc struct {
	Go        []byte
	RawSchema []byte
	Schema    *jsonschema.Schema
}

func (doc *Doc) Render(w io.Writer, name string) error {
	u, err := urn.Parse(name)
	if err != nil {
		return err
	}
	n, err := u.Name()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "## ")
	if doc.Schema != nil && doc.Schema.Title != "" {
		fmt.Fprintln(w, doc.Schema.Title)
	} else {
		fmt.Fprintln(w, n.Kind+":"+n.Name)
	}
	fmt.Fprintf(w, "|||\n|:-|:-|\n|Name|`%v`|\n\n", &n)
	w.Write(doc.Go)
	fmt.Fprintln(w)
	if doc.Schema != nil {
		var m map[string]any
		json.Unmarshal(doc.RawSchema, &m)
		delete(m, "examples")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")

		fmt.Fprintln(w, "### Configuration")
		fmt.Fprintln(w, doc.Schema.Description)
		if ex := doc.Schema.Examples; len(ex) != 0 {
			fmt.Fprintln(w, "<details><summary><b>Examples</b></summary>")
			fmt.Fprintln(w)
			for _, ex := range ex {
				fmt.Fprintln(w, "```json")
				enc.Encode(ex)
				fmt.Fprintln(w, "```")
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "</details>")
		}
		fmt.Fprintln(w, "<details><summary><b>Schema</b></summary>")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "```json")
		enc.Encode(m)
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "</details>")
		fmt.Fprintln(w)
	}
	return nil
}

func docSetup() (docMap, error) {
	jsc := jsonschema.NewCompiler()
	jsc.Draft = jsonschema.Draft2020
	jsc.ExtractAnnotations = true
	jsc.AssertFormat = true
	jsc.AssertContent = true
	jsc.LoadURL = func(s string) (io.ReadCloser, error) {
		if s == `urn:claircore:config:empty` {
			return io.NopCloser(strings.NewReader(plugin.MustBeEmpty)), nil
		}
		return jsonschema.LoadURL(s)
	}
	pkgs, err := Directives(`github.com/quay/claircore`)
	if err != nil {
		return nil, err
	}
	docs := make(map[string]map[string]map[string]*Doc)
	for _, pkg := range pkgs {
	Directive:
		for _, d := range pkg.Directive {
			if len(d.Args) < 2 {
				continue
			}
			// Setup
			cmd, ok := docs[d.Args[0]]
			if !ok {
				cmd = make(map[string]map[string]*Doc)
				docs[d.Args[0]] = cmd
			}
			scope, ok := cmd[d.Args[1]]
			if !ok {
				scope = make(map[string]*Doc)
				cmd[d.Args[1]] = scope
			}
			var name string
			if len(d.Args) > 2 {
				name = d.Args[2]
			} else {
				name, err = findName(pkg.Package, d.Node)
				if err != nil {
					return nil, err
				}
			}
			doc := &Doc{}
			scope[name] = doc

			// Big imperative ball of crap:
			var spec *ast.ValueSpec
			switch x := d.Node.(type) {
			case *ast.GenDecl:
				doc.Go = mdPrint.Markdown(mdParser.Parse(x.Doc.Text()))
				spec = x.Specs[0].(*ast.ValueSpec)
			case *ast.ValueSpec:
				doc.Go = mdPrint.Markdown(mdParser.Parse(x.Doc.Text()))
				spec = x
			default:
				return nil, fmt.Errorf("directive found associated with unexpected type: %T (%v)", x, pkg.Fset.Position(x.Pos()))
			}

			val := spec.Values[0].(*ast.CompositeLit)
			for _, elt := range val.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if id.Name != "ConfigSchema" {
					continue
				}
				switch v := kv.Value.(type) {
				case *ast.Ident:
					decl := v.Obj.Decl
					switch x := decl.(type) {
					case *ast.ValueSpec:
						i := 0
						for ; x.Names[i].Name != v.Name; i++ {
						}
						if ct := len(x.Values); ct != 0 && i < ct {
							switch x := x.Values[i].(type) {
							case *ast.BasicLit:
								cs, err := strconv.Unquote(x.Value)
								if err != nil {
									return nil, err
								}
								doc.RawSchema = []byte(cs)
								if err := jsc.AddResource(name, strings.NewReader(cs)); err != nil {
									return nil, err
								}
								doc.Schema, err = jsc.Compile(name)
								if err != nil {
									return nil, err
								}
								continue Directive
							case *ast.BinaryExpr:
								return nil, fmt.Errorf("%v: cannot use concatenated strings", pkg.Fset.Position(v.Pos()))
							default:
								return nil, fmt.Errorf("%v: unexpected type %T", pkg.Fset.Position(v.Pos()), x)
							}
						}
						// Check for embed
						const embedPrefix = `//go:embed`
						if group := x.Doc; group != nil {
							for _, c := range group.List {
								if strings.HasPrefix(c.Text, embedPrefix) {
									var p string
									ok := false
									base := strings.TrimSpace(c.Text[len(embedPrefix):])
									for _, n := range pkg.EmbedFiles {
										if strings.HasSuffix(n, base) {
											ok = true
											p = n
										}
									}
									if !ok {
										return nil, fmt.Errorf("%v: weird embed", pkg.Fset.Position(c.Slash))
									}
									b, err := os.ReadFile(p)
									if err != nil {
										return nil, err
									}
									doc.RawSchema = b
									if err := jsc.AddResource(name, bytes.NewReader(b)); err != nil {
										return nil, err
									}
									doc.Schema, err = jsc.Compile(name)
									if err != nil {
										return nil, err
									}
									continue Directive
								}
							}
						}
						return nil, fmt.Errorf("%[2]v: unable to handle %[1]v", x, pkg.Fset.Position(x.Pos()))
					default:
						return nil, fmt.Errorf("%[3]v: unexpected type for %[1]q: %[2]T", "ConfigSchema", x, pkg.Fset.Position(x.(ast.Node).Pos()))
					}
				case *ast.BasicLit:
					cs, err := strconv.Unquote(v.Value)
					if err != nil {
						return nil, err
					}
					doc.RawSchema = []byte(cs)
					if err := jsc.AddResource(name, strings.NewReader(cs)); err != nil {
						return nil, err
					}
					doc.Schema, err = jsc.Compile(name)
					if err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("unexpected type for %q: %T (%v)", "ConfigSchema", v, pkg.Fset.Position(v.Pos()))
				}
			}
		}
	}

	return docs, nil
}

var (
	mdParser = comment.Parser{}
	mdPrint  = comment.Printer{
		HeadingLevel: 3,
		TextWidth:    -1,
	}
)

func findName(pkg *packages.Package, n ast.Node) (string, error) {
	var spec *ast.ValueSpec
	switch x := n.(type) {
	case *ast.GenDecl:
		spec = x.Specs[0].(*ast.ValueSpec)
	case *ast.ValueSpec:
		spec = x
	default:
		return "", fmt.Errorf("directive found associated with unexpected type: %T (%v)", x, pkg.Fset.Position(x.Pos()))
	}
	guess := strings.TrimSuffix(spec.Names[0].Name, "Description") + "Name"
	var decl *ast.GenDecl
	for _, f := range pkg.Syntax {
		ast.Inspect(f, IdentExists(&decl, guess))
		if decl != nil {
			break
		}
	}
	if decl == nil {
		return "", fmt.Errorf("in %q: unable to find expected ident %q", pkg.PkgPath, guess)
	}
	var name string
	switch decl.Tok {
	case token.VAR, token.CONST:
		spec := decl.Specs[0].(*ast.ValueSpec)
		lit := spec.Values[0].(*ast.BasicLit)
		name = lit.Value
	default:
		return "", fmt.Errorf("directive found associated with unexpected type: %T (%v)", decl, pkg.Fset.Position(decl.Pos()))
	}
	return strconv.Unquote(name)
}
