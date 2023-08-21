// Command plugintool handles code generation and documentation processing for
// claircore's plugin system.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
)

func main() {
	// Flags
	var (
		packageName *string
		scope       *string
		outFile     string
		mdbookMode  bool
	)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("plugintool: ")
	flag.Func("name", "package name for generated file (defaults to package in working directory)", func(v string) error {
		if packageName != nil {
			return errors.New(`"name" specified multiple times`)
		}
		packageName = &v
		return nil
	})
	flag.Func("scope", `"scope" package to register plugins for (relative to the main module)`, func(v string) error {
		if packageName != nil {
			return errors.New(`"scope" specified multiple times`)
		}
		scope = &v
		return nil
	})
	flag.StringVar(&outFile, "out", "plugin_init.go", "output file name ('-' for stdout)")
	flag.BoolVar(&mdbookMode, "mdbook", false, "run in mdbook preprocessor mode")
	flag.Parse()
	ctx := context.Background()
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer done()

	root, err := findRoot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	switch {
	case mdbookMode:
		err = runMdbook(ctx, root)
	default:
		if scope == nil {
			log.Fatalln(`missing needed flag "scope"`)
		}
		var out io.Reader
		out, err = runCodegen(ctx, root, *scope, packageName)
		if err != nil {
			break
		}
		var w io.Writer
		if outFile != "" && outFile != "-" {
			f, err := os.OpenFile(outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				break
			}
			defer f.Close()
			w = f
		} else {
			w = os.Stdout
		}
		_, err = io.Copy(w, out)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func findRoot(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, `git`, `rev-parse`, `--show-toplevel`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error calling %q: %#q", "git", string(out))
	} else {
		return string(bytes.TrimSpace(out)), nil
	}
	return "", errors.New("TODO: walk around a bit looking for the go.mod")
}
