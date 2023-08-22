// Package mdbook is a helper for writing mdbook plugins.
package mdbook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
)

// Main is a simple replacement main for mdbook preprocessors.
func Main(name string, pf ProcFunc) {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix(name + ": ")
	Args(os.Args)

	err := func() error {
		ctx := context.Background()
		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
		defer cancel()

		cfg, book, err := Decode(os.Stdin)
		if err != nil {
			return err
		}
		proc, err := pf(ctx, cfg)
		if err != nil {
			return err
		}

		if err := proc.Walk(ctx, book); err != nil {
			return err
		}

		if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		log.Fatal(err)
	}
}

// ProcFunc is a hook for creating a new Proc.
type ProcFunc func(context.Context, *Context) (*Proc, error)

// Args implements handling the expected CLI arguments.
//
// This function calls [os.Exit] under the right circumstances.
func Args(argv []string) {
	// Handle when called with "supports $renderer".
	if len(argv) != 3 {
		return
	}
	switch argv[1] {
	case "supports":
		switch argv[2] {
		case "html":
		default:
			log.Printf("unsupported renderer: %q", argv[2])
			os.Exit(1)
		}
	default:
		log.Printf("unknown subcommand: %q", argv[1])
		os.Exit(1)
	}
	os.Exit(0)
}

// Decode reads the [Context] and [Book] JSON objects from the passed
// [io.Reader]. This should be almost always be [os.Stdin].
func Decode(r io.Reader) (*Context, *Book, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if r, ok := tok.(json.Delim); !ok || r != '[' {
		return nil, nil, fmt.Errorf("unexpected start of input: %v", tok)
	}

	var ppContext Context
	if err := dec.Decode(&ppContext); err != nil {
		return nil, nil, err
	}
	var book Book
	if err := dec.Decode(&book); err != nil {
		return nil, nil, err
	}

	tok, err = dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if r, ok := tok.(json.Delim); !ok || r != ']' {
		return nil, nil, fmt.Errorf("unexpected end of input: %v", tok)
	}

	return &ppContext, &book, nil
}

// Proc is a helper for modifying a [Book].
type Proc struct {
	Chapter   Hook[Chapter]
	Separator Hook[Separator]
	PartTitle Hook[PartTitle]
}

// Hook is a hook function to modify a BookItem in-place.
type Hook[I BookItem] func(ctx context.Context, b *strings.Builder, item *I) error

// BookItem is one of [Chapter], [Separator], or [PartTitle].
type BookItem interface {
	Chapter | Separator | PartTitle
}

// Walk walks the provided [Book], calling the [Hook]s in the member fields as
// needed to modify elements in-place.
func (p *Proc) Walk(ctx context.Context, book *Book) error {
	var b strings.Builder
	var err error
	for _, sec := range book.Sections {
		err = p.section(ctx, &b, sec)
		if err != nil {
			return err
		}
	}
	return nil
}

// Section calls the relevant hooks on the current [Section].
func (p *Proc) section(ctx context.Context, b *strings.Builder, s Section) (err error) {
	b.Reset()
	switch {
	case s.Separator != nil:
		if p.Separator != nil {
			err = p.Separator(ctx, b, s.Separator)
		}
	case s.PartTitle != nil:
		if p.PartTitle != nil {
			err = p.PartTitle(ctx, b, s.PartTitle)
		}
	case s.Chapter != nil:
		if p.Chapter != nil {
			err = p.Chapter(ctx, b, s.Chapter)
			if err != nil {
				break
			}
		}
		for _, s := range s.Chapter.SubItems {
			err = p.section(ctx, b, s)
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	return nil
}

// Context is the whole mdbook context.
type Context struct {
	Root     string `json:"root"`
	Renderer string `json:"renderer"`
	Version  string `json:"mdbook_version"`
	Config   struct {
		Book   BookConfig                 `json:"book"`
		Output map[string]json.RawMessage `json:"output"`
	} `json:"config"`
	Preprocessor map[string]json.RawMessage `json:"preprocessor"`
}

// BookConfig is the mdbook metadata and configuration.
type BookConfig struct {
	Authors      []string `json:"authors"`
	Source       string   `json:"src"`
	Description  string   `json:"description"`
	Language     string   `json:"language"`
	Title        string   `json:"title"`
	MultiLingual bool     `json:"multilingual"`
}

// Book is an mdbook book.
type Book struct {
	Sections []Section `json:"sections"`
	X        *struct{} `json:"__non_exhaustive"`
}

// Section is one of a [Chapter], [Separator], or [PartTitle].
type Section struct {
	Chapter   *Chapter   `json:",omitempty"`
	Separator *Separator `json:",omitempty"`
	PartTitle *PartTitle `json:",omitempty"`
}

// Separator denotes an mdbook separator.
type Separator struct{}

// PartTitle is the title of the current part.
type PartTitle string

// Chapter is an mdbook chapter.
type Chapter struct {
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	Number      []int     `json:"number"`
	SubItems    []Section `json:"sub_items"`
	Path        *string   `json:"path"`
	SourcePath  *string   `json:"source_path"`
	ParentNames []string  `json:"parent_names"`
}
