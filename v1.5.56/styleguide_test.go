package docs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/sync/errgroup"
)

// StripCodeBlocks removes fenced code blocks from markdown content.
// The .*? is non-greedy to stop at the first closing ``` rather than the last.
var stripCodeBlocks = regexp.MustCompile("(?s)```.*?```")

func TestStyleguide(t *testing.T) {
	eg, ctx := errgroup.WithContext(context.Background())
	names := make(chan string)
	findMarkdown := func(p string, dirent fs.DirEntry, err error) error {
		switch {
		case !errors.Is(err, nil):
			return err
		case dirent.IsDir():
			return nil
		case filepath.Ext(p) != ".md":
			return nil
		}
		select {
		case <-ctx.Done():
			return fs.SkipAll
		case names <- p:
		}
		return nil
	}
	runlint := func() error {
		rules := []struct {
			Name        string
			Regexp      *regexp.Regexp
			Explanation string
		}{
			{
				Name:        "NoIntercap",
				Regexp:      regexp.MustCompile(`[Cc]lairCore`),
				Explanation: `should not be inter-capped`,
			},
			{
				Name:        "NoIntercap",
				Regexp:      regexp.MustCompile(`[Ll]ibVuln`),
				Explanation: `should not be inter-capped`,
			},
			{
				Name:        "NoIntercap",
				Regexp:      regexp.MustCompile(`[Ll]ibIndex`),
				Explanation: `should not be inter-capped`,
			},
			{
				Name:        "RespectPostgreSQL",
				Regexp:      regexp.MustCompile(`[Pp]ostgres([Qq][Ll])?`),
				Explanation: `it's spelled "PostgreSQL"`,
			},
			{
				Name:        "RespectClair",
				Regexp:      regexp.MustCompile(`[Cc]lair[Vv]4`),
				Explanation: `it's spelled "Clair v4"`,
			},
		}
		for fn := range names {
			b, err := os.ReadFile(fn)
			if err != nil {
				return err
			}

			// Strip code blocks before applying rules
			prose := stripCodeBlocks.ReplaceAll(b, nil)

			for _, rule := range rules {
				for _, idx := range rule.Regexp.FindAllIndex(prose, -1) {
					t.Errorf("%s:%d: %q\t[%s: %s]", fn, idx[0], string(prose[idx[0]:idx[1]]), rule.Name, rule.Explanation)
				}
			}

		}
		return nil
	}
	eg.Go(func() error {
		defer close(names)
		return fs.WalkDir(os.DirFS("."), ".", findMarkdown)
	})
	eg.Go(runlint)

	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
}
