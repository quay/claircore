package main

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/crgimenes/goconfig"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	libhttp "github.com/quay/claircore/libvuln/http"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/ubuntu"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr string `cfgDefault:"0.0.0.0:8081" cfg:"HTTP_LISTEN_ADDR"`
	DataStore      string `cfgDefault:"postgres" cfg:"DATASTORE" cfgHelper:"DataStore that libvuln will connect to. currently implemented: 'postgres'`
	ConnString     string `cfgDefault:"host=localhost port=5435 user=libvuln dbname=libvuln password=libvuln sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	UpdateLock     string `cfgDefault:"postgres" cfg"UPDATE_LOCK" cfgHelper:"ScanLock that libvuln should use. currently implemented: 'postgres'"`
	LogLevel       string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
}

func main() {
	ctx := context.Background()
	// parse our config
	conf := Config{}
	err := goconfig.Parse(&conf)
	if err != nil {
		log.Fatal().Msgf("failed to parse config: %v", err)
	}

	// setup pretty logging
	zerolog.SetGlobalLevel(logLevel(conf))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	opts := confToLibvulnOpts(conf)

	// create libvuln
	lib, err := libvuln.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libvuln %v", err)
	}

	httpServ := httpServer(conf, lib)
	log.Printf("starting http server on %v", conf.HTTPListenAddr)
	err = httpServ.ListenAndServe()
	if err != nil {
		log.Fatal().Msgf("failed to start http server: %v", err)
	}

}

func logLevel(conf Config) zerolog.Level {
	level := strings.ToLower(conf.LogLevel)
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

func httpServer(conf Config, lib libvuln.Libvuln) *http.Server {
	// create our http mux and add routes
	mux := http.NewServeMux()

	// create server and launch in go routine
	s := &http.Server{
		Addr:    conf.HTTPListenAddr,
		Handler: mux,
	}

	// create handlers
	mux.Handle("/scan", libhttp.VulnScan(lib))

	return s
}

func confToLibvulnOpts(conf Config) *libvuln.Opts {
	matchers := []driver.Matcher{
		&debian.Matcher{},
		&ubuntu.Matcher{},
	}
	updaters := []driver.Updater{
		ubuntu.NewUpdater(ubuntu.Artful),
		ubuntu.NewUpdater(ubuntu.Bionic),
		ubuntu.NewUpdater(ubuntu.Cosmic),
		ubuntu.NewUpdater(ubuntu.Disco),
		ubuntu.NewUpdater(ubuntu.Precise),
		ubuntu.NewUpdater(ubuntu.Trusty),
		ubuntu.NewUpdater(ubuntu.Xenial),
		debian.NewUpdater(debian.Buster),
		debian.NewUpdater(debian.Jessie),
		debian.NewUpdater(debian.Stretch),
		debian.NewUpdater(debian.Wheezy),
	}

	for _, v := range []rhel.Release{
		rhel.RHEL6,
		rhel.RHEL7,
		rhel.RHEL8,
	} {
		u, err := rhel.NewUpdater(v)
		if err != nil {
			log.Fatal().Msgf("unable to create rhel updater: %v", err)
		}
		updaters = append(updaters, u)
	}

	opts := &libvuln.Opts{
		Matchers: matchers,
		Updaters: updaters,
	}

	// parse DataStore
	switch conf.DataStore {
	case string(libvuln.Postgres):
		opts.DataStore = libvuln.DataStore(conf.DataStore)
		opts.ConnString = conf.ConnString
	default:
		log.Fatal().Msgf("the DataStore %s is not implemented", conf.DataStore)
	}

	// parse UpdateLock
	switch conf.UpdateLock {
	case string(libvuln.PostgresSL):
		opts.UpdateLock = libvuln.UpdateLock(conf.UpdateLock)
	default:
		log.Fatal().Msgf("the ScanLock %s is not implemented", conf.UpdateLock)
	}

	return opts
}
