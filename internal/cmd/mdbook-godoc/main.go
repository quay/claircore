// Mdbook-godoc is a helper meant to inline `go doc` output.
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
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/quay/claircore/internal/mdbook"
)

var marker = regexp.MustCompile(`\{\{#\s*godoc\s(.+)\}\}`)

func main() {
	mdbook.Main("godoc", newProc)
}

func newProc(ctx context.Context, cfg *mdbook.Context) (*mdbook.Proc, error) {
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
	return &proc, nil
}
