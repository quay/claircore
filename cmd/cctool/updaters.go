package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/internal/vulnstore/jsonblob"
	"github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/pyupio"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
)

func RunUpdaters(cmd context.Context, cfg *commonConfig, args []string) error {
	ctx, cancel := context.WithCancel(cmd)
	defer cancel()
	var (
		// Strict controls whether the command should exit non-zero if any
		// updater fails.
		strict bool
	)
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
	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)
	ctx = log.WithContext(ctx)

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

	u, err := libvuln.NewOfflineUpdater(nil, nil, out)
	if err != nil {
		return err
	}

	ufs := []driver.UpdaterSetFactory{
		&ubuntu.Factory{Releases: ubuntu.Releases},
		driver.UpdaterSetFactoryFunc(alpine.UpdaterSet),
		driver.UpdaterSetFactoryFunc(aws.UpdaterSet),
		driver.UpdaterSetFactoryFunc(debian.UpdaterSet),
		driver.UpdaterSetFactoryFunc(oracle.UpdaterSet),
		driver.UpdaterSetFactoryFunc(photon.UpdaterSet),
		driver.UpdaterSetFactoryFunc(pyupio.UpdaterSet),
		driver.UpdaterSetFactoryFunc(suse.UpdaterSet),
	}
	if f, err := rhel.NewFactory(ctx, rhel.DefaultManifest); err == nil {
		ufs = append(ufs, f)
	} else {
		return err
	}

	if err := u.RunUpdaters(ctx, ufs...); err != nil {
		if strict {
			return err
		}
		log.Warn().Err(err).Send()
	}
	return nil
}

func LoadUpdates(cmd context.Context, cfg *commonConfig, args []string) error {
	ctx, cancel := context.WithCancel(cmd)
	defer cancel()
	var (
		cfgFile string
	)
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
	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)
	ctx = log.WithContext(ctx)

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

	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	s := postgres.NewVulnStore(pool)
	l, err := jsonblob.Load(ctx, gz)
	ops, err := s.GetUpdateOperations(ctx)
	if err != nil {
		return err
	}

Update:
	for l.Next() {
		e := l.Entry()
		for _, op := range ops[e.Updater] {
			// This only helps if updaters don't keep something that
			// changes in the fingerprint.
			if op.Fingerprint == e.Fingerprint {
				fmt.Printf("%s: skip\n", e.Updater)
				continue Update
			}
		}
		ref, err := s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s (%d vulns)\n", e.Updater, ref, len(e.Vuln))
	}
	if err := l.Err(); err != nil {
		return err
	}
	return nil
}

type Config struct {
	Matcher struct {
		ConnString string `yaml:"connstring"`
	} `yaml:"matcher"`
}
