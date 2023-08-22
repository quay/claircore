//go:build ignore

// Godoc is a helper meant to inline `go doc` output.
//
// Any preprocessor directive like
//
//	{{# godoc <arg>... }}
//
// Will have the equivalent of `go doc arg...` run and inserted as code blocks.
package main

// BUG(hank) This package should use the `go/doc/comment` package to generate
// HTML or Markdown.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"

	"github.com/quay/claircore/internal/mdbook"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("godoc: ")
	mdbook.Args(os.Args)

	cfg, book, err := mdbook.Decode(os.Stdin)
	if err != nil {
		panic(err)
	}
	marker := regexp.MustCompile(`\{\{#\s*godoc\s(.+)\}\}`)
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	proc := mdbook.Proc{
		Chapter: func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
			if c.Path == nil {
				return nil
			}
			var print sync.Once
			var ret error
			c.Content = marker.ReplaceAllStringFunc(c.Content, func(sub string) string {
				print.Do(func() { log.Println("inserting docs into:", *c.Path) })
				ms := marker.FindStringSubmatch(sub)
				if ct := len(ms); ct != 2 {
					ret = fmt.Errorf("unexpected number of arguments: %d", ct)
					return sub
				}

				cmd := exec.CommandContext(ctx, `go`, append([]string{"doc"}, strings.Fields(ms[1])...)...)
				cmd.Dir = cfg.Root
				out, err := cmd.Output()
				if err != nil {
					ret = err
					return sub
				}
				b.WriteString("```\n")
				if _, err := b.Write(bytes.TrimSpace(out)); err != nil {
					ret = err
					return sub
				}
				b.WriteString("\n```")
				return b.String()
			})
			return ret
		},
	}
	if err := proc.Walk(ctx, book); err != nil {
		panic(err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
		panic(err)
	}
}
