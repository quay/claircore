//go:build go1.24

// The cleancache tool cleans local caches for testing.
package main

import (
	"context"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/quay/claircore/test/internal/cache"
)

var dryRunFlag bool

func main() {
	var errExit bool
	defer func() {
		if errExit {
			os.Exit(1)
		}
	}()
	ctx := context.Background()
	flag.BoolVar(&dryRunFlag, "n", false, "dry-run")
	flag.Parse()

	todo := DoNone
Args:
	for _, arg := range flag.Args() {
		switch strings.ToLower(arg) {
		case "all":
			todo = DoAll
			break Args
		case "layer", "layers":
			todo |= DoLayers
		default:
			slog.ErrorContext(ctx, "unknown argument", "argument", arg)
			errExit = true
			return
		}
	}
	if todo == DoNone {
		slog.ErrorContext(ctx, "not asked to do anything; want arguments of: all, layers")
		errExit = true
		return
	}

	if err := Main(ctx, todo); err != nil {
		errExit = true
	}
}

type Which uint

const (
	DoNone Which = 0
	DoAll  Which = ^DoNone
)

const (
	DoLayers = 1 << iota
	// TODO(hank) Use these:
	DoDatabases
	DoGenerated
)

func Main(ctx context.Context, todo Which) error {
	if todo&DoLayers != 0 {
		root, err := cache.Root(cache.Layer)
		if err != nil {
			return err
		}
		defer root.Close()
		slog.InfoContext(ctx, "cleaning cached layers", "dir", root.Name(), "dry-run", dryRunFlag)

		var errs []error
		err = fs.WalkDir(root.FS(), ".", func(p string, ent fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case ent.IsDir():
				return nil
			}
			l := slog.With("name", p)

			l.InfoContext(ctx, "found file, removing")
			if dryRunFlag {
				return nil
			}
			if err := root.Remove(p); err != nil {
				l.ErrorContext(ctx, "unable to remove file", "reason", err)
				errs = append(errs, err)
			}
			return nil
		})

		if err := errors.Join(append(errs, err)...); err != nil {
			return err
		}
	}

	return nil
}
