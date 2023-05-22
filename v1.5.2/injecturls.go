//go:build ignore
// +build ignore

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
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("injecturls: ")

	// Handle when called with "supports $renderer".
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "supports":
			switch os.Args[2] {
			case "html":
			default:
				os.Exit(1)
			}
		default:
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Actual preprocessing mode.
	log.Println("running preprocessor")

	in := make([]json.RawMessage, 2)
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		panic(err)
	}
	var cfg Config
	if err := json.Unmarshal(in[0], &cfg); err != nil {
		panic(err)
	}
	var book Book
	if err := json.Unmarshal(in[1], &book); err != nil {
		panic(err)
	}

	var b strings.Builder
	for _, s := range book.Sections {
		if err := s.Process(&b, &cfg); err != nil {
			panic(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
		panic(err)
	}
}

// in: {"root":"/var/home/hank/work/clair/clair","config":{"book":{"authors":["Clair Authors"],"description":"Documentation for Clair.","language":"en","multilingual":false,"src":"Documentation","title":"Clair Documentation"},"output":{"html":{"git-repository-url":"https://github.com/quay/clair","preferred-dark-theme":"coal"}},"preprocessor":{"history":{"command":"go run Documentation/history.go"}}},"renderer":"html","mdbook_version":"0.4.13"}
type Config struct {
	Root     string `json:"root"`
	Renderer string `json:"renderer"`
	Version  string `json:"mdbook_version"`
	Config   struct {
		Book BookConfig `json:"book"`
	} `json:"config"`
}

type BookConfig struct {
	Source string `json:"src"`
}

type Book struct {
	Sections []Section `json:"sections"`
	X        *struct{} `json:"__non_exhaustive"`
}

type Section struct {
	Chapter   *Chapter    `json:",omitempty"`
	Separator interface{} `json:",omitempty"`
	PartTitle string      `json:",omitempty"`
}

func (s *Section) Process(b *strings.Builder, cfg *Config) error {
	if s.Chapter != nil {
		return s.Chapter.Process(b, cfg)
	}
	return nil
}

type Chapter struct {
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	Number      []int     `json:"number"`
	SubItems    []Section `json:"sub_items"`
	Path        *string   `json:"path"`
	SourcePath  *string   `json:"source_path"`
	ParentNames []string  `json:"parent_names"`
}

func (c *Chapter) Process(b *strings.Builder, cfg *Config) error {
	if c.Path != nil && marker.MatchString(c.Content) {
		ms := marker.FindStringSubmatch(c.Content)
		if ct := len(ms); ct != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", ct)
		}
		keyword := strings.TrimSpace(ms[1])
		log.Println("injecting urls into:", *c.Path)
		var collect []string
		err := filepath.WalkDir(cfg.Root, func(p string, d fs.DirEntry, err error) error {
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
			ast.Inspect(f, func(n ast.Node) bool {
				decl, ok := n.(*ast.GenDecl)
				if !ok {
					return true
				}
				if decl.Tok != token.CONST && decl.Tok != token.VAR {
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
			})
			return nil
		})
		if err != nil {
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
	}
	for _, s := range c.SubItems {
		if err := s.Process(b, cfg); err != nil {
			return err
		}
	}
	return nil
}

var (
	marker    = regexp.MustCompile(`\{\{#\s*injecturls\s(.+)\}\}`)
	printverb = regexp.MustCompile(`%[+#]*[a-z]`)
)
