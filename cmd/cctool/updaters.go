package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"gopkg.in/yaml.v3"

	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/jsonblob"
	"github.com/quay/claircore/libvuln/updates"
	_ "github.com/quay/claircore/updater/defaults"
)

func RunUpdaters(cmd context.Context, cfg *commonConfig, args []string) error {
	ctx, cancel := context.WithCancel(cmd)
	defer cancel()

	// Strict controls whether the command should exit non-zero if any
	// updater fails.
	var strict bool
	fs := flag.NewFlagSet("cctool run-updaters", flag.ExitOnError)
	fs.BoolVar(&strict, "strict", false, "exit non-zero is any updater fails")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "\tcctool run-updaters [outfile]\n")
		fmt.Fprintf(out, "Arguments:\n")
		fmt.Fprintf(out, "\toutfile: a filename to write results to. (default: stdout)\n\n")
	}
	fs.Parse(args)

	var out io.Writer
	switch len(fs.Args()) {
	case 0:
		out = os.Stdout
		defer os.Stdout.Sync()
	case 1:
		f, err := os.Create(fs.Arg(0))
		if err != nil {
			return err
		}
		defer func() {
			f.Sync()
			f.Close()
		}()
		out = f
	default:
		fs.Usage()
		return nil
	}

	store, err := jsonblob.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Store(out); err != nil {
			zlog.Warn(ctx).Err(err).Send()
		}
	}()
	mgr, err := updates.NewManager(ctx, store, updates.NewLocalLockSource(), http.DefaultClient)
	if err != nil {
		return err
	}
	if err := mgr.Run(ctx); err != nil {
		if strict {
			return err
		}
		zlog.Warn(ctx).Err(err).Send()
	}
	return nil
}

func LoadUpdates(cmd context.Context, cfg *commonConfig, args []string) error {
	ctx, cancel := context.WithCancel(cmd)
	defer cancel()
	var cfgFile string
	fs := flag.NewFlagSet("cctool load-updates", flag.ExitOnError)
	fs.StringVar(&cfgFile, "config", "", "file to read database configuration from ")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "\tcctool load-updates [-config file] [infile]\n")
		fmt.Fprintf(out, "Arguments:\n")
		fmt.Fprintf(out, "\tinfile: a filename to read results from. (default: stdin)\n\n")
	}
	fs.Parse(args)

	dsn := os.Getenv("CONNECTION_STRING")
	if cfgFile != "" {
		f, err := os.Open(cfgFile)
		if err != nil {
			return err
		}
		defer f.Close()
		var cfg Config
		if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
			return err
		}
		dsn = cfg.Matcher.ConnString
	}

	pool, err := pgxpool.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	var in io.Reader
	switch len(fs.Args()) {
	case 0:
		in = os.Stdin
	case 1:
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	default:
		fs.Usage()
		return nil
	}

	if err := libvuln.OfflineImport(ctx, pool, in); err != nil {
		return err
	}
	return nil
}

type Config struct {
	Matcher struct {
		ConnString string `yaml:"connstring"`
	} `yaml:"matcher"`
}
