package main

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/crgimenes/goconfig"
	"github.com/quay/claircore/libindex"
	libhttp "github.com/quay/claircore/libindex/http"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr       string `cfgDefault:"0.0.0.0:8080" cfg:"HTTP_LISTEN_ADDR"`
	ConnString           string `cfgDefault:"host=localhost port=5434 user=libindex dbname=libindex password=libindex sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	ScanLockRetry        int    `cfgDefault:"1" cfg:"SCAN_LOCK_RETRY" cfgHelper:"Time in seconds libindex should retry a manifest scan if it detects another process is doing the same"`
	LayerScanConcurrency int    `cfgDefault:"10" cfg:"LAYER_SCAN_CONCURRENCY" cfgHelper:"The number of layers libindex will scan concurrently per manifest scan"`
	LogLevel             string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
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

	opts := confTolibindexOpts(conf)

	// create libindex
	lib, err := libindex.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libindex %v", err)
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

func httpServer(conf Config, lib libindex.Libindex) *http.Server {
	// create our http mux and add routes
	mux := http.NewServeMux()

	// create server and launch in go routine
	s := &http.Server{
		Addr:    conf.HTTPListenAddr,
		Handler: mux,
	}

	// create handlers
	mux.Handle("/index", libhttp.Index(lib))
	mux.Handle("/index_report/", libhttp.IndexReport(lib))

	return s
}

func confTolibindexOpts(conf Config) *libindex.Opts {
	opts := &libindex.Opts{
		ConnString: conf.ConnString,
	}

	return opts
}
