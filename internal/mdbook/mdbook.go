// Package mdbook is a helper for writing mdbook plugins.
package mdbook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// RegisterFunc is the type for arranging to have a preprocessor's hooks called.
//
// Implmentations should use the passed [context.Context] and [Context], then
// call functions to register hooks in the [Proc] as needed.
type RegisterFunc func(context.Context, *Context, *Proc) error

// NewProc returns a [Proc] with the provided [RegisterFunc]s called on it.
func NewProc(ctx context.Context, cfg *Context, fs ...RegisterFunc) (*Proc, error) {
	var p Proc
	for _, f := range fs {
		if err := f(ctx, cfg, &p); err != nil {
			return nil, err
		}
	}
	return &p, nil
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
	chapter   []Hook[Chapter]
	separator []Hook[Separator]
	partTitle []Hook[PartTitle]
}

// Hook is a hook function to modify a BookItem in-place.
type Hook[I BookItem] func(ctx context.Context, b *strings.Builder, item *I) error

// BookItem is one of [Chapter], [Separator], or [PartTitle].
type BookItem interface {
	Chapter | Separator | PartTitle
}

// Chapter registers a [Chapter] [Hook].
func (p *Proc) Chapter(h Hook[Chapter]) {
	p.chapter = append(p.chapter, h)
}

// Separator registers a [Separator] [Hook].
func (p *Proc) Separator(h Hook[Separator]) {
	p.separator = append(p.separator, h)
}

// PartTitle registers a [PartTitle] [Hook].
func (p *Proc) PartTitle(h Hook[PartTitle]) {
	p.partTitle = append(p.partTitle, h)
}

// Walk walks the provided [Book], calling the [Hook]s in the member fields as
// needed to modify elements in-place.
func (p *Proc) Walk(ctx context.Context, book *Book) error {
	var b strings.Builder
	var err error
	for _, it := range book.Items {
		err = p.item(ctx, &b, it)
		if err != nil {
			return err
		}
	}
	return nil
}

// Item calls the relevant hooks on the current [Item].
func (p *Proc) item(ctx context.Context, b *strings.Builder, s Item) error {
	var errs []error
	switch {
	case s.Separator != nil:
		for _, f := range p.separator {
			b.Reset()
			errs = append(errs, f(ctx, b, s.Separator))
		}
	case s.PartTitle != nil:
		for _, f := range p.partTitle {
			b.Reset()
			errs = append(errs, f(ctx, b, s.PartTitle))
		}
	case s.Chapter != nil:
		for _, f := range p.chapter {
			b.Reset()
			errs = append(errs, f(ctx, b, s.Chapter))
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
		for _, s := range s.Chapter.SubItems {
			if err := p.item(ctx, b, s); err != nil {
				errs = append(errs, err)
				break
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
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
	Items []Item    `json:"items"`
	X     *struct{} `json:"__non_exhaustive"`
}

// Item is one of a [Chapter], [Separator], or [PartTitle].
type Item struct {
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
	Name        string   `json:"name"`
	Content     string   `json:"content"`
	Number      []int    `json:"number"`
	SubItems    []Item   `json:"sub_items"`
	Path        *string  `json:"path"`
	SourcePath  *string  `json:"source_path"`
	ParentNames []string `json:"parent_names"`
}
