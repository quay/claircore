// Mdbook-make_target is a helper to check that documented Makefile targets exist.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/quay/claircore/internal/mdbook"
)

var (
	open     sync.Once
	makefile []byte
)

func readMakefile(ctx context.Context) {
	cmd := exec.CommandContext(ctx, `git`, `rev-parse`, `--show-toplevel`)
	out, err := cmd.Output()
	if err != nil {
		log.Panic(err)
	}
	n := filepath.Join(string(bytes.TrimSpace(out)), `Makefile`)
	makefile, err = os.ReadFile(n)
	if err != nil {
		log.Panic(err)
	}
}

var marker = regexp.MustCompile(`\{\{#\s*make_target\s(.+)\}\}`)

func main() {
	mdbook.Main("make_target", newProc)
}

func newProc(_ context.Context, _ *mdbook.Context) (*mdbook.Proc, error) {
	proc := mdbook.Proc{
		Chapter: func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
			if c.Path == nil {
				return nil
			}
			var ret error
			c.Content = marker.ReplaceAllStringFunc(c.Content, func(sub string) string {
				ms := marker.FindStringSubmatch(sub)
				if ct := len(ms); ct != 2 {
					ret = fmt.Errorf("unexpected number of arguments: %d", ct)
					return sub
				}
				target := strings.TrimSpace(ms[1])
				re, err := regexp.Compile("\n" + target + `:`)
				if err != nil {
					ret = err
					return sub
				}
				open.Do(func() { readMakefile(ctx) })
				if !re.Match(makefile) {
					ret = fmt.Errorf("unable to find target %q", target)
				}
				log.Printf("found target: %q", target)
				return target
			})
			return ret
		},
	}
	return &proc, nil
}
