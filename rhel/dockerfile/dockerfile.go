// Package dockerfile implements a minimal dockerfile parser.
package dockerfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
)

// GetLabels parses the Dockerfile in the provided Reader and returns all
// discovered labels as provided by the LABEL instruction, with variables
// resolved and expanded.
//
// ARG and ENV instructions are understood. This will yield different results
// if a build argument is supplied at build time.
func GetLabels(_ context.Context, r io.Reader) (map[string]string, error) {
	p := getParser()
	defer putParser(p)
	p.Init(r)
	return p.Labels, p.Run()
}

type labelParser struct {
	Labels  map[string]string
	lex     *lexer
	unquote *Unquote
	vars    *Vars
	escchar rune
}

func newLabelParser() *labelParser {
	return &labelParser{
		unquote: NewUnquote(),
		vars:    NewVars(),
		lex:     newLexer(),
	}
}

// Init sets up the parser to read from r.
func (p *labelParser) Init(r io.Reader) {
	p.Labels = make(map[string]string)
	p.lex.Reset(r)
	p.vars.Clear()
	p.Escape('\\')
}

// Escape sets the escape metacharacter for the lexer and the current
// transformers.
func (p *labelParser) Escape(r rune) {
	p.escchar = r
	p.lex.Escape(p.escchar)
	p.unquote.Escape(p.escchar)
	p.vars.Escape(p.escchar)
}

// Run consumes items and keeps track of variables and labels.
//
// A nil error is reported on encountering io.EOF.
func (p *labelParser) Run() error {
	var i item
	for i = p.lex.Next(); ; i = p.lex.Next() {
		switch i.kind {
		case itemEOF:
			return nil
		case itemError:
			return errors.New(i.val)
		case itemEnv:
			idxEq := strings.IndexByte(i.val, '=')
			idxSp := strings.IndexFunc(i.val, unicode.IsSpace)
			if idxEq == -1 || (idxSp != -1 && idxSp < idxEq) {
				// If there's no "=", or there are both "=" and whitespace but
				// the whitespace comes first, this is an `ENV NAME VALUE`
				// instruction.
				k, _, err := transform.String(p.unquote, i.val[:idxSp])
				if err != nil {
					return err
				}
				v, _, err := transform.String(p.vars, strings.TrimLeftFunc(i.val[idxSp:], unicode.IsSpace))
				if err != nil {
					return err
				}
				p.vars.Set(k, v)
			} else {
				// This is a bunch of k=v pairs. First, we need to split the
				// pairs. Values can be quoted strings, so using FieldsFunc is
				// incorrect.
				pairs, err := splitKV(p.escchar, i.val)
				if err != nil {
					return err
				}
				for _, kv := range pairs {
					i := strings.IndexByte(kv, '=')
					k, _, err := transform.String(p.unquote, kv[:i])
					if err != nil {
						return err
					}
					v, _, err := transform.String(transform.Chain(p.unquote, p.vars), kv[i+1:])
					if err != nil {
						return err
					}
					p.vars.Set(k, v)
				}
			}
		case itemArg:
			idx := strings.IndexByte(i.val, '=')
			if idx == -1 {
				continue
			}
			k, _, err := transform.String(p.unquote, i.val[:idx])
			if err != nil {
				return err
			}
			v, _, err := transform.String(transform.Chain(p.unquote, p.vars), i.val[idx+1:])
			if err != nil {
				return err
			}
			p.vars.Set(k, v)
		case itemLabel:
			pairs, err := splitKV(p.escchar, i.val)
			if err != nil {
				return err
			}
			for _, kv := range pairs {
				i := strings.IndexByte(kv, '=')
				k, _, err := transform.String(p.unquote, kv[:i])
				if err != nil {
					return err
				}
				v, _, err := transform.String(transform.Chain(p.unquote, p.vars), kv[i+1:])
				if err != nil {
					return err
				}
				p.Labels[k] = v
			}
		case itemComment:
			v := strings.ToLower(strings.TrimSpace(i.val))
			if strings.Contains(v, `escape=`) {
				eq := strings.IndexByte(v, '=')
				if eq == -1 {
					return fmt.Errorf("botched parser directive: %#q", i.val)
				}
				esc, _ := utf8.DecodeRuneInString(v[:eq+1])
				p.lex.Escape(esc)
				p.unquote.Escape(esc)
				p.vars.Escape(esc)
			}
		default: // discard
		}
	}
}

// SplitKV splits a string on unquoted or un-escaped whitespace.
//
// Label and Env instructions allow for key-value pairs with this syntax.
func splitKV(escchar rune, in string) ([]string, error) {
	var ret []string
	var esc, quote bool
	var quotechar rune
	start := 0
	for cur, r := range in {
		switch {
		case esc:
			esc = false
		case !esc && r == escchar:
			esc = true
		case !esc && !quote && (r == '"' || r == '\''):
			quote = true
			quotechar = r
		case !esc && quote && r == quotechar:
			quote = false
			quotechar = 0
		case !esc && !quote && isWhitespace(r):
			runlen := cur - start
			switch {
			case runlen > 1:
				ret = append(ret, in[start:cur])
				fallthrough
			case runlen == 1:
				start = cur + 1
			default: // advance
			}
		default: // advance
		}
	}
	if rem := in[start:]; len(rem) > 0 {
		ret = append(ret, rem)
	}
	return ret, nil
}

// IsWhitespace reports whether the rune is valid intraline whitespace.
func isWhitespace(r rune) bool {
	return unicode.IsSpace(r) && r != '\n'
}
