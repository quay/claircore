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
			if err := p.handleAssign(i.val, p.vars.Set); err != nil {
				return err
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
			// NOTE(hank) This sucks. This is not documented to work this way
			// but experimentally, does.
			//	skopeo inspect docker://registry.redhat.io/rhel7/etcd:3.2.32-14
			if err := p.handleAssign(i.val, func(k, v string) { p.Labels[k] = v }); err != nil {
				return err
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

// HandleAssign handles the assignment commands.
//
// Only `ENV` commands should have this ambiguity in their handling, but some
// Dockerfiles in the wild have `LABEL` commands that work this way, also.
func (p *labelParser) handleAssign(val string, f func(k, v string)) error {
	if isKV(val) {
		// This is a bunch of k=v pairs. First, we need to split the pairs.
		// Values can be quoted strings, so using FieldsFunc is incorrect.
		pairs, err := splitKV(p.escchar, val)
		if err != nil {
			return err
		}
		for _, kv := range pairs {
			idx := strings.IndexByte(kv, '=')
			if idx == -1 {
				return fmt.Errorf(`invalid assignment syntax: %+#q`, val)
			}
			k, _, err := transform.String(p.unquote, kv[:idx])
			if err != nil {
				return err
			}
			v, _, err := transform.String(transform.Chain(p.unquote, p.vars), kv[idx+1:])
			if err != nil {
				return err
			}
			f(k, v)
		}
		return nil
	}
	idxSp := strings.IndexFunc(val, unicode.IsSpace)
	k, _, err := transform.String(p.unquote, val[:idxSp])
	if err != nil {
		return err
	}
	v, _, err := transform.String(p.vars, strings.TrimLeftFunc(val[idxSp:], unicode.IsSpace))
	if err != nil {
		return err
	}
	f(k, v)
	return nil
}

// SplitKV splits a string on unquoted or un-escaped whitespace.
//
// Label and Env instructions allow for key-value pairs with this syntax.
func splitKV(escchar rune, in string) ([]string, error) {
	var ret []string
	var esc, quote, ws bool
	var quotechar rune
	start := 0
	for cur, r := range in {
	Backup:
		switch {
		case esc:
			esc = false
		case !esc && r == escchar:
			esc = true
		case !esc && !quote && (r == '"' || r == '\''):
			if ws {
				// If this ends a whitespace run, update the starting position.
				start = cur
			}
			ws = false
			quote = true
			quotechar = r
		case !esc && quote && r == quotechar:
			quote = false
			quotechar = 0
		case !esc && !quote && ws:
			// In a run of unquoted whitespace.
			if isWhitespace(r) {
				break
			}
			// A non-quote character has ended the whitespace run; reset flags
			// and re-process the character.
			start = cur
			ws = false
			goto Backup
		case !esc && !quote && isWhitespace(r):
			ret = append(ret, in[start:cur])
			ws = true
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

func isKV(s string) bool {
	idxEq := strings.IndexByte(s, '=')
	idxSp := strings.IndexFunc(s, unicode.IsSpace)
	return idxEq != -1 && (idxSp == -1 || idxSp >= idxEq)
}
