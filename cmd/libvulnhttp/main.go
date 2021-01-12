package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/crgimenes/goconfig"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/updater/defaults"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr           string `cfgDefault:"0.0.0.0:8081" cfg:"HTTP_LISTEN_ADDR"`
	MaxConnPool              int    `cfgDefault:"100" cfg:"MAX_CONN_POOL" cfgHelper:"the maximum size of the connection pool used for database connections"`
	ConnString               string `cfgDefault:"host=localhost port=5434 user=claircore dbname=claircore sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	Run                      string `cfg:"RUN" cfgDefault:"." cfgHelper:"Regexp of updaters to run."`
	LogLevel                 string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
	Migrations               bool   `cfgDefault:"true" cfg:"MIGRATIONS" cfgHelper:"Should server run migrations"`
	DisableBackgroundUpdates bool   `cfgDefault:"false" cfg:"DISABLE_BACKGROUND_UPDATES" cfgHelper:"Should matcher regularly update vulnerability database"`
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

	// create libvuln
	opts := confToLibvulnOpts(conf)
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

func confToLibvulnOpts(conf Config) *libvuln.Opts {
	opts := &libvuln.Opts{
		ConnString:               conf.ConnString,
		MaxConnPool:              int32(conf.MaxConnPool),
		Migrations:               true,
		UpdaterSets:              nil,
		DisableBackgroundUpdates: conf.DisableBackgroundUpdates,
	}
	re, err := regexp.Compile(conf.Run)
	if err == nil {
		opts.UpdaterFilter = re.MatchString
	}

	return opts
}
