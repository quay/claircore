// Bisect is a git bisect helper.
//
// It relies on some makefile targets to spin up and down all services and wraps
// calls to cctool.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

func main() {
	var exit int
	defer func() {
		if exit != 0 {
			os.Exit(exit)
		}
	}()
	args := Args{}
	flag.BoolVar(&args.Verbose, "v", false, "verbose output")
	flag.BoolVar(&args.Warmup, "warmup", false, "do a warmup run before making any requests.")
	flag.String("dump-manifest", "{{.}}.manifest.json", "dump manifest to templated location, if provided")
	flag.String("dump-index", "{{.}}.index.json", "dump index to templated location, if provided")
	flag.String("dump-report", "{{.}}.report.json", "dump report to templated location, if provided")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "dump-manifest":
			if f.Value.String() == "" {
				f.Value.Set(f.DefValue)
			}
			v := f.Value.String()
			args.DumpManifest = &v
		case "dump-index":
			if f.Value.String() == "" {
				f.Value.Set(f.DefValue)
			}
			v := f.Value.String()
			args.DumpIndex = &v
		case "dump-report":
			if f.Value.String() == "" {
				f.Value.Set(f.DefValue)
			}
			v := f.Value.String()
			args.DumpReport = &v
		}
	})

	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer done()
	if err := Main(ctx, args, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit = 1
	}
}

type Args struct {
	DumpManifest *string
	DumpIndex    *string
	DumpReport   *string
	Verbose      bool
	Warmup       bool
}

func Main(ctx context.Context, args Args, imgs []string) error {
	if err := checkDeps(ctx); err != nil {
		return err
	}
	root, err := findRoot(ctx)
	if err != nil {
		return err
	}
	workDir := filepath.Join(root, `test/bisect`)
	cmd := exec.CommandContext(ctx, "go", "test", "-tags", "integration", "-c")
	cmd.Dir = workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	if flag.NArg() == 0 {
		flag.PrintDefaults()
		return errors.New("no arguments given")
	}

	if args.Warmup {
		cmd = exec.CommandContext(ctx, filepath.Join(workDir, `bisect.test`), "-enable")
		if args.Verbose {
			cmd.Args = append(cmd.Args, "-stderr")
		}
		cmd.Dir = workDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	cmd = exec.CommandContext(ctx, filepath.Join(workDir, `bisect.test`), "-enable")
	if args.Verbose {
		cmd.Args = append(cmd.Args, "-stderr")
	}
	if f := args.DumpManifest; f != nil {
		p, err := filepath.Abs(*f)
		if err != nil {
			return err
		}
		cmd.Args = append(cmd.Args, "-dump-manifest", p)
	}
	if f := args.DumpIndex; f != nil {
		p, err := filepath.Abs(*f)
		if err != nil {
			return err
		}
		cmd.Args = append(cmd.Args, "-dump-index", p)
	}
	if f := args.DumpReport; f != nil {
		p, err := filepath.Abs(*f)
		if err != nil {
			return err
		}
		cmd.Args = append(cmd.Args, "-dump-report", p)
	}
	cmd.Args = append(cmd.Args, imgs...)
	cmd.Dir = workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func findRoot(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	cmd.Stderr = nil
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
}

func checkDeps(_ context.Context) error {
	for _, exe := range []string{
		"git",
		"skopeo",
	} {
		if _, err := exec.LookPath(exe); err != nil {
			return err
		}
	}
	return nil
}
