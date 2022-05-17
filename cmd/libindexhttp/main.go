package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/crgimenes/goconfig"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/pkg/ctxlock"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr       string `cfgDefault:"0.0.0.0:8080" cfg:"HTTP_LISTEN_ADDR"`
	ConnString           string `cfgDefault:"host=localhost port=5434 user=claircore dbname=claircore sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	ScanLockRetry        int    `cfgDefault:"1" cfg:"SCAN_LOCK_RETRY" cfgHelper:"Time in seconds libindex should retry a manifest scan if it detects another process is doing the same"`
	LayerScanConcurrency int    `cfgDefault:"10" cfg:"LAYER_SCAN_CONCURRENCY" cfgHelper:"The number of layers libindex will scan concurrently per manifest scan"`
	LogLevel             string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
}

func main() {
	ctx := context.Background()
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true}).
		With().Timestamp().Caller().
		Logger()

	// parse our config
	conf := Config{}
	err := goconfig.Parse(&conf)
	if err != nil {
		log.Fatal().Msgf("failed to parse config: %v", err)
	}

	// configure logging
	log = log.Level(logLevel(conf))
	zlog.Set(&log)

	pool, err := postgres.InitDB(ctx, conf.ConnString, "libindex")
	if err != nil {
		log.Fatal().Msgf("failed to create db pool: %v", err)
	}
	store, err := postgres.InitPostgresIndexerStore(ctx, pool, true)
	if err != nil {
		log.Fatal().Msgf("failed to create store: %v", err)
	}

	opts := &libindex.Options{
		Store:      store,
		Locker:     &ctxlock.Locker{},
		FetchArena: libindex.NewRemoteFetchArena(http.DefaultClient, os.TempDir()),
	}

	// create libindex
	lib, err := libindex.New(ctx, opts, http.DefaultClient)
	if err != nil {
		log.Fatal().Msgf("failed to create libindex %v", err)
	}
	defer lib.Close(ctx)

	h := libindex.NewHandler(lib)
	srv := &http.Server{
		Addr:        conf.HTTPListenAddr,
		Handler:     h,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	zlog.Info(ctx).Str("addr", conf.HTTPListenAddr).Msg("starting http server")
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatal().Msgf("failed to start http server: %v", err)
	}
}

func logLevel(conf Config) zerolog.Level {
	if l, err := zerolog.ParseLevel(strings.ToLower(conf.LogLevel)); err == nil {
		return l
	}
	return zerolog.InfoLevel
}
