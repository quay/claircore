// Package godoc is an mdbook preprocessor to inline `go doc` output.
//
// Any preprocessor directive like
//
//	{{# godoc <arg>... }}
//
// Will have the equivalent of `go doc arg...` run and inserted as code blocks.
package godoc

// BUG(hank) This package should use the `go/doc/comment` package to generate
// HTML or Markdown.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/quay/claircore/internal/mdbook"
)

var marker = regexp.MustCompile(`\{\{#\s*godoc\s(.+)\}\}`)

// Register registers the preprocessor.
func Register(ctx context.Context, cfg *mdbook.Context, p *mdbook.Proc) error {
	pkgcfg := packages.Config{
		Context: ctx,
		Mode:    packages.LoadImports | packages.LoadAllSyntax,
	}
	pkgs, err := packages.Load(&pkgcfg, "./...")
	if err != nil {
		return err
	}
	slices.SortFunc(pkgs, func(a, b *packages.Package) int {
		return strings.Compare(a.PkgPath, b.PkgPath)
	})
	chapter := func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
		if c.Path == nil {
			return nil
		}
		var logline sync.Once
		var ret error
		repl := func(sub string) string {
			logline.Do(func() { log.Println("inserting docs into:", *c.Path) })
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
			b.WriteString("\n```\n")
			return b.String()
		}
		c.Content = marker.ReplaceAllStringFunc(c.Content, repl)
		return ret
	}
	p.Chapter(chapter)
	return nil
}
