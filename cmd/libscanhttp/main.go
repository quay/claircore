package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crgimenes/goconfig"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/libscan"
	libhttp "github.com/quay/claircore/libscan/http"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config this struct is using the goconfig library for simple flag and env var
// parsing. See: https://github.com/crgimenes/goconfig
type Config struct {
	HTTPListenAddr       string `cfgDefault:"0.0.0.0:8080" cfg:"HTTP_LISTEN_ADDR"`
	DataStore            string `cfgDefault:"postgres" cfg:"DATASTORE" cfgHelper:"DataStore that libscan will connect to. currently implemented: 'postgres'`
	ConnString           string `cfgDefault:"host=localhost port=5434 user=libscan dbname=libscan password=libscan sslmode=disable" cfg:"CONNECTION_STRING" cfgHelper:"Connection string for the provided DataStore"`
	ScanLock             string `cfgDefault:"postgres" cfg"SCAN_LOCK" cfgHelper:"ScanLock that libscan should use. currently implemented: 'postgres'"`
	ScanLockRetry        int    `cfgDefault:"1" cfg:"SCAN_LOCK_RETRY" cfgHelper:"Time in seconds libscan should retry a manifest scan if it detects another process is doing the same"`
	LayerScanConcurrency int    `cfgDefault:"10" cfg:"LAYER_SCAN_CONCURRENCY" cfgHelper:"The number of layers libscan will scan concurrently per manifest scan"`
	LayerFetchOption     string `cfgDefault:"inmem" cfg:"LAYER_FETCH_OPTION" cfgHelper:"How libscan will download images. currently supported: 'inmem', 'ondisk'`
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

	opts := confToLibscanOpts(conf)

	// create libscan
	lib, err := libscan.New(ctx, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create libscan %v", err)
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

func httpServer(conf Config, lib libscan.Libscan) *http.Server {
	// create our http mux and add routes
	mux := http.NewServeMux()

	// create server and launch in go routine
	s := &http.Server{
		Addr:    conf.HTTPListenAddr,
		Handler: mux,
	}

	// create handlers
	mux.Handle("/scan", libhttp.Scan(lib))
	mux.Handle("/scanreport/", libhttp.ScanReport(lib))

	return s
}

func confToLibscanOpts(conf Config) *libscan.Opts {
	opts := &libscan.Opts{
		DataStore:  libscan.Postgres,
		ConnString: "postgres://host:port",
		ScanLock:   libscan.PostgresSL,
		Ecosystems: []*scanner.Ecosystem{
			dpkg.NewEcosystem(context.Background()),
		},
	}

	// parse DataStore
	switch conf.DataStore {
	case string(libscan.Postgres):
		opts.DataStore = libscan.DataStore(conf.DataStore)
		opts.ConnString = conf.ConnString
	default:
		log.Fatal().Msgf("the DataStore %s is not implemented", conf.DataStore)
	}

	// parse ScanLock
	switch conf.ScanLock {
	case string(libscan.PostgresSL):
		opts.ScanLock = libscan.ScanLock(conf.ScanLock)
	default:
		log.Fatal().Msgf("the ScanLock %s is not implemented", conf.ScanLock)
	}

	// parse ScanLockRetry
	slrDur := time.Duration(conf.ScanLockRetry) * time.Second
	opts.ScanLockRetry = slrDur

	// parse layerfetchoption
	switch conf.LayerFetchOption {
	case string(scanner.InMem):
		opts.LayerFetchOpt = scanner.LayerFetchOpt(conf.LayerFetchOption)
	case string(scanner.OnDisk):
		opts.LayerFetchOpt = scanner.LayerFetchOpt(conf.LayerFetchOption)
	default:
		log.Fatal().Msgf("the LayerFetchOption %s is not implemented", conf.LayerFetchOption)
	}

	return opts
}
