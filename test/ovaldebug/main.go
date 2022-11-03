// Ovaldebug is a helper for debugging the ovalutil package.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/claircore/rhel"
)

func main() {
	flavor := flag.String("flavor", "rpm", "OVAL flavor")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "missing required argument(s): database URLs")
		flag.Usage()
		os.Exit(1)
	}
	ctx := context.Background()
	log.Logger = zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = os.Stderr })).
		Level(zerolog.DebugLevel)

	for _, u := range flag.Args() {
		u, err := url.Parse(u)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		ext := strings.TrimPrefix(path.Ext(path.Base(u.Path)), ".")
		if ext == "xml" {
			ext = ""
		}

		cmp, err := ovalutil.ParseCompressor(ext)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		f := ovalutil.Fetcher{
			Compression: cmp,
			URL:         u,
			Client:      http.DefaultClient,
		}

		rc, _, err := f.Fetch(ctx, "")
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		defer rc.Close()

		var vs []*claircore.Vulnerability
		switch *flavor {
		case "rpm":
			var u driver.Updater
			u, err = rhel.NewUpdater("rhel-test", 8, "file:///dev/null")
			if err != nil {
				log.Fatal().Err(err).Send()
			}
			vs, err = u.Parse(ctx, rc)
		case "debian":
		/*
			u := debian.NewUpdater(debian.Buster)
			vs, err = u.Parse(ctx, rc)
		*/
		case "ubuntu":
			log.Fatal().Str("flavor", *flavor).Msg("ubuntu unsupported in this tool")
		case "dpkg":
			log.Fatal().Str("flavor", *flavor).Msg("unimplemented oval flavor")
		default:
			log.Fatal().Str("flavor", *flavor).Msg("unknown oval flavor")
		}

		if err != nil {
			log.Info().Err(err).Msg("error during extraction")
		}
		_ = vs
	}
}

var _ ovalutil.ProtoVulnsFunc = pf

func pf(def oval.Definition) ([]*claircore.Vulnerability, error) {
	return nil, nil
}
