package dockerfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

/*
This lexer is based on the text/template lexer, which has the same recursive
function construction.

Parser directives are handled by the parser.  Trailing whitespace is not passed
to the parser, which may or may not be significant. This is not a
general-purpose dockerfile lexer, it's only intended to handle just enough of
valid dockerfiles to extract the labels.
*/

type lexer struct {
	rd      *bufio.Reader
	state   lexFn
	sb      strings.Builder
	items   chan item
	pos     int
	escchar rune
}

func newLexer() *lexer {
	return &lexer{
		state: start,
		rd:    bufio.NewReader(nil),
	}
}

// Reset resets the lexer to read from r.
func (l *lexer) Reset(r io.Reader) {
	// The strings.Builder is handled by the 'start' state.
	l.rd.Reset(r)
	l.items = make(chan item, 1)
	l.pos = 0
	l.escchar = '\\'
	l.state = start
}

// Escape changes the escape metacharacter (used for line continuations).
func (l *lexer) Escape(r rune) {
	l.escchar = r
}

type item struct {
	val  string
	kind itemKind
	pos  int
}

type itemKind int

//go:generate stringer -type itemKind $GOFILE

const (
	itemError itemKind = iota
	itemComment
	itemInstruction
	itemLabel
	itemArg
	itemEnv
	itemEOF
)

const eof = -1

type lexFn func(*lexer) lexFn

// Next yields the next item.
func (l *lexer) Next() item {
	// The text/template lexer this is based on uses a goroutine, but that's not
	// workable because we need to be able to swap the escape metacharacter
	// after the lexer has started running, and without restarting. A goroutine
	// would make reads and writes on l.escchar race.
	//
	// This construction uses a buffered channel to stash one item and the fact
	// that a nil channel never succeeds in a select switch.
	for l.state != nil {
		select {
		case i := <-l.items:
			if i.kind == itemEOF {
				close(l.items)
				l.items = nil
			}
			return i
		default:
			l.state = l.state(l)
		}
	}
	return item{kind: itemEOF}
}

func (l *lexer) consumeWhitespace() (err error) {
	var r rune
	var sz int
	for r, sz, err = l.rd.ReadRune(); err == nil; r, sz, err = l.rd.ReadRune() {
		if !unicode.IsSpace(r) {
			err = l.rd.UnreadRune()
			break
		}
		l.pos += sz
	}
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, io.EOF):
	default:
		return err
	}
	return nil
}

func (l *lexer) collectLine() (err error) {
	var r rune
	var sz int
	var esc, inComment, started bool
Read:
	for r, sz, err = l.rd.ReadRune(); err == nil; r, sz, err = l.rd.ReadRune() {
		switch {
		case inComment && r == '\n':
			inComment = false
			started = false
		case inComment: // Skip
		case esc && r == '\r': // Lexer hack: why do some things have DOS line endings?
		case esc && r == '\n':
			esc = false
			started = false
		case esc:
			// This little lexer only cares about constructing the lines
			// correctly, so everything else gets passed through.
			esc = false
			sz, _ := l.sb.WriteRune(l.escchar)
			l.pos += sz
			_, err = l.sb.WriteRune(r)
		case r == l.escchar:
			esc = true
			started = true
		case !esc && r == '\n':
			err = l.rd.UnreadRune()
			break Read
		case !started && !esc && r == '#':
			inComment = true
		case !started:
			if !unicode.IsSpace(r) {
				started = true
			}
			fallthrough
		default:
			_, err = l.sb.WriteRune(r)
		}
		if err != nil {
			break Read
		}
		l.pos += sz
	}
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, io.EOF):
	default:
		return err
	}
	return nil
}

func (l *lexer) error(e error) lexFn {
	switch {
	case errors.Is(e, nil): // ???
	case errors.Is(e, io.EOF):
		l.items <- item{kind: itemEOF}
	default:
		l.items <- item{val: e.Error(), kind: itemError, pos: l.pos}
	}
	return nil
}

func (l *lexer) peek() rune {
	r, _, err := l.rd.ReadRune()
	if errors.Is(err, io.EOF) {
		return eof
	}
	l.rd.UnreadRune()
	return r
}

func start(l *lexer) lexFn {
	l.sb.Reset()
	if err := l.consumeWhitespace(); err != nil {
		return l.error(err)
	}
	switch r := l.peek(); {
	case r == '#':
		return lexComment
	case unicode.IsLetter(r):
		return lexInstruction
	case r == eof:
		l.items <- item{kind: itemEOF}
	default:
		return l.error(fmt.Errorf("unknown rune %q", r))
	}
	return nil
}

func lexComment(l *lexer) lexFn {
	l.rd.ReadRune() // comment marker
	if err := l.consumeWhitespace(); err != nil {
		return l.error(err)
	}
	if err := l.collectLine(); err != nil {
		return l.error(err)
	}
	l.items <- item{
		val:  l.sb.String(),
		kind: itemComment,
		pos:  l.pos,
	}
	return start
}

func lexInstruction(l *lexer) lexFn {
	if err := l.collectLine(); err != nil {
		return l.error(err)
	}

	ln := l.sb.String()
	i := strings.IndexFunc(ln, unicode.IsSpace)
	if i == -1 {
		return l.error(fmt.Errorf("unexpected line: %#q", ln))
	}
	cmd := ln[:i]
	rest := strings.TrimSpace(ln[i:])
	switch {
	case strings.EqualFold(cmd, `arg`):
		l.items <- item{
			val:  rest,
			kind: itemArg,
			pos:  l.pos,
		}
	case strings.EqualFold(cmd, `env`):
		l.items <- item{
			val:  rest,
			kind: itemEnv,
			pos:  l.pos,
		}
	case strings.EqualFold(cmd, `label`):
		l.items <- item{
			val:  rest,
			kind: itemLabel,
			pos:  l.pos,
		}
	default:
		l.items <- item{
			val:  l.sb.String(),
			kind: itemInstruction,
			pos:  l.pos,
		}
	}
	return start
}
