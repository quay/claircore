package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/crgimenes/goconfig"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/updater/defaults"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr           string `cfgDefault:"0.0.0.0:8081" cfg:"HTTP_LISTEN_ADDR"`
	MaxConnPool              int    `cfgDefault:"100" cfg:"MAX_CONN_POOL" cfgHelper:"the maximum size of the connection pool used for database connections"`
	ConnString               string `cfgDefault:"host=localhost port=5434 user=claircore dbname=claircore sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	LogLevel                 string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
	Migrations               bool   `cfgDefault:"true" cfg:"MIGRATIONS" cfgHelper:"Should server run migrations"`
	DisableBackgroundUpdates bool   `cfgDefault:"false" cfg:"DISABLE_BACKGROUND_UPDATES" cfgHelper:"Should matcher regularly update vulnerability database"`
	DeadlyHTTPClient         bool   `cfgDefault:"false" cfg:"DEADLY_HTTP_CLIENT" cfgHelper:"Poison the net/http default transport and client"`
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
	if err := defaults.Error(); err != nil {
		log.Fatal().Err(err).Msg("default updaters errored on construction")
	}
	// configure logging
	log = log.Level(logLevel(conf))
	zlog.Set(&log)

	// HTTP client config
	if conf.DeadlyHTTPClient {
		http.DefaultClient = &http.Client{
			Transport: new(nofun),
		}
		http.DefaultTransport = nil
		origClient.Transport = origTransport
	}

	pool, err := postgres.Connect(ctx, conf.ConnString, "libindexhttp")
	if err != nil {
		log.Fatal().Msgf("failed to create db pool: %v", err)
	}
	store, err := postgres.InitPostgresMatcherStore(ctx, pool, true)
	if err != nil {
		log.Fatal().Msgf("failed to create store: %v", err)
	}

	// create libvuln
	opts := confToLibvulnOpts(conf, store)
	lib, err := libvuln.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libvuln %v", err)
	}

	h := libvuln.NewHandler(lib)
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
	if l, err := zerolog.ParseLevel(strings.ToLower(conf.LogLevel)); err == nil {
		return l
	}
	return zerolog.InfoLevel
}

func confToLibvulnOpts(conf Config, store datastore.MatcherStore) *libvuln.Options {
	opts := &libvuln.Options{
		Store:                    store,
		Locker:                   &ctxlock.Locker{},
		UpdaterSets:              nil,
		DisableBackgroundUpdates: conf.DisableBackgroundUpdates,
		UpdateInterval:           1 * time.Minute,
		UpdateWorkers:            10,
		UpdateRetention:          10,
		Client:                   origClient,
	}

	return opts
}

var (
	origTransport = http.DefaultTransport.(*http.Transport).Clone()
	origClient    = http.DefaultClient
)

type nofun struct{}

func (_ *nofun) RoundTrip(_ *http.Request) (*http.Response, error) {
	_, file, line, ok := runtime.Caller(6) // determined experimentally
	if ok {
		return nil, fmt.Errorf("request denied by policy; occurred at %s:%d", file, line)
	}
	return nil, errors.New("request denied by policy")
}
