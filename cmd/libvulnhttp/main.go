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

	"github.com/quay/claircore/libvuln"
	libhttp "github.com/quay/claircore/libvuln/http"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr string `cfgDefault:"0.0.0.0:8081" cfg:"HTTP_LISTEN_ADDR"`
	MaxConnPool    int    `cfgDefault:"100" cfg:"MAX_CONN_POOL" cfgHelper:"the maximum size of the connection pool used for database connections"`
	ConnString     string `cfgDefault:"host=localhost port=5434 user=claircore dbname=claircore sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	Run            string `cfg:"RUN" cfgDefault:"." cfgHelper:"Regexp of updaters to run."`
	LogLevel       string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
	Migrations     bool   `cfgDefault:"true" cfg:"MIGRATIONS" cfgHelper:"Should server run migrations"`
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

	opts := confToLibvulnOpts(conf)

	// create libvuln
	lib, err := libvuln.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libvuln %v", err)
	}

	httpServ := httpServer(ctx, conf, lib)
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

func httpServer(ctx context.Context, conf Config, lib *libvuln.Libvuln) *http.Server {
	// create our http mux and add routes
	mux := http.NewServeMux()

	// create server and launch in go routine
	s := &http.Server{
		Addr:        conf.HTTPListenAddr,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	// create handlers
	mux.Handle("/scan", libhttp.VulnScan(lib))

	return s
}

func confToLibvulnOpts(conf Config) *libvuln.Opts {
	opts := &libvuln.Opts{
		ConnString:  conf.ConnString,
		MaxConnPool: int32(conf.MaxConnPool),
		Migrations:  true,
		UpdaterSets: nil,
	}

	return opts
}
