package main

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	libhttp "github.com/quay/claircore/libvuln/http"
	"github.com/quay/claircore/pkg/tracing"
	"github.com/quay/claircore/ubuntu"

	"github.com/crgimenes/goconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr      string `cfgDefault:"0.0.0.0:8081" cfg:"HTTP_LISTEN_ADDR"`
	DataStore           string `cfgDefault:"postgres" cfg:"DATASTORE" cfgHelper:"DataStore that libvuln will connect to. currently implemented: 'postgres'`
	ConnString          string `cfgDefault:"host=localhost port=5435 user=libvuln dbname=libvuln password=libvuln sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	UpdateLock          string `cfgDefault:"postgres" cfg:"UPDATE_LOCK" cfgHelper:"ScanLock that libvuln should use. currently implemented: 'postgres'"`
	LogLevel            string `cfgDefault:"debug" cfg:"LOG_LEVEL" cfgHelper:"Log levels: debug, info, warning, error, fatal, panic" `
	MaxConnPool         int    `cfgDefault:"100" cfg:"MAX_CONN_POOL" cfgHelper:"the maximum size of the connection pool used for database connections"`
	Run                 string `cfg:"RUN" cfgDefault:"." cfgHelper:"Regexp of updaters to run."`
	JaegerAgentHostPort string `cfgDefault:"localhost:6831" cfg:"JAEGER_AGENT_HOST_PORT" cfgHelper:"The location for the Jaeger Agent, when available. Leaving empty disables tracing." `
}

func main() {
	// parse our config
	conf := Config{}
	err := goconfig.Parse(&conf)
	if err != nil {
		log.Fatal().Msgf("failed to parse config: %v", err)
	}

	// setup pretty logging
	zerolog.SetGlobalLevel(logLevel(conf))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	tracing.Bootstrap(conf.JaegerAgentHostPort)

	opts := confToLibvulnOpts(conf)

	// create libvuln
	ctx := context.Background()
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
		&alpine.Matcher{},
	}

	ups, err := updaters()
	if err != nil {
		log.Fatal().Msgf("%v", err)
	}

	// filter out updaters not matching provided regex
	ups, err = regexFilter(conf.Run, ups)
	if err != nil {
		log.Fatal().Msgf("%v", err)
	}

	opts := &libvuln.Opts{
		Matchers: matchers,
		Updaters: ups,
		Tracer:   tracing.GetTracer("claircore/libvuln"),
	}

	// parse DataStore
	switch conf.DataStore {
	case string(libvuln.Postgres):
		opts.DataStore = libvuln.DataStore(conf.DataStore)
		opts.ConnString = conf.ConnString
	default:
		log.Fatal().Msgf("the DataStore %s is not implemented", conf.DataStore)
	}

	// set max connection pool option
	opts.MaxConnPool = int32(conf.MaxConnPool)

	// parse UpdateLock
	switch conf.UpdateLock {
	case string(libvuln.PostgresSL):
		opts.UpdateLock = libvuln.UpdateLock(conf.UpdateLock)
	default:
		log.Fatal().Msgf("the ScanLock %s is not implemented", conf.UpdateLock)
	}

	return opts
}
