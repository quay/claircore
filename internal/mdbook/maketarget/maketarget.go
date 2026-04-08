// Package maketarget is an mdbook preprocessor to check that documented
// Makefile targets exist.
package maketarget

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/quay/claircore/internal/mdbook"
)

var makefile = sync.OnceValues(func() ([]byte, error) {
	return os.ReadFile(filepath.Join(".", "Makefile"))
})

var marker = regexp.MustCompile(`\{\{#\s*make_target\s(.+)\}\}`)

// Register registers the preprocessor.
func Register(_ context.Context, _ *mdbook.Context, p *mdbook.Proc) error {
	if _, err := makefile(); err != nil {
		return err
	}
	p.Chapter(chapter)
	return nil
}

func chapter(_ context.Context, _ *strings.Builder, c *mdbook.Chapter) error {
	if c.Path == nil {
		return nil
	}
	var ret error
	repl := func(sub string) string {
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
		b, _ := makefile()
		if !re.Match(b) {
			ret = fmt.Errorf("unable to find target %q", target)
		}
		log.Printf("found target: %q", target)
		return target
	}
	c.Content = marker.ReplaceAllStringFunc(c.Content, repl)
	return ret
}
