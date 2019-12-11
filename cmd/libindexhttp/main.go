package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/crgimenes/goconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore/libindex"
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
	ctx = log.Logger.WithContext(ctx)

	opts := &libindex.Opts{
		ConnString: conf.ConnString,
		Migrations: true,
	}

	// create libindex
	lib, err := libindex.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libindex %v", err)
	}

	h := libindex.NewHandler(lib)
	srv := &http.Server{
		Addr:        conf.HTTPListenAddr,
		Handler:     h,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	log.Printf("starting http server on %v", conf.HTTPListenAddr)
	err = srv.ListenAndServe()
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
