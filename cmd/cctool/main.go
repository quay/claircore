package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"text/template"
)

var cleanup sync.WaitGroup

type commonConfig struct {
	UseDocker   bool
	URLTemplate *template.Template
}

type subcmd func(context.Context, *commonConfig, []string) error

func main() {
	var exit int
	defer func() {
		if exit != 0 {
			os.Exit(exit)
		}
	}()
	ctx, done := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		done()
	}()
	var err error

	var cfg commonConfig
	fs := flag.NewFlagSet("main", flag.ExitOnError)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage of %s:\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nSubcommands\n\n")
		fmt.Fprintln(out, "report")
		fmt.Fprintln(out, "\tgenerate reports for containers provided as arguments or on stdin")
		fmt.Fprintln(out)
	}

	fs.BoolVar(&cfg.UseDocker, "d", false, "use 'docker' tools instead of 'skopeo'")
	tmplString := fs.String("f", `http://localhost/{{.Hash}}`, "template string for generating layer URLs")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	cfg.URLTemplate, err = template.New("url").Parse(*tmplString)
	if err != nil {
		log.Fatal(err)
	}

	var cmd subcmd
	switch n := fs.Arg(0); n {
	case "report":
		cmd = Report
	case "":
		fs.Usage()
		os.Exit(99)
	default:
		fs.Usage()
		fmt.Fprintf(os.Stderr, "\nunknown subcommand %q\n", n)
		os.Exit(99)
	}

	var cmdErr error
	cmdctx, cmddone := context.WithCancel(ctx)
	go func() {
		defer cmddone()
		cmdErr = cmd(cmdctx, &cfg, fs.Args()[1:])
	}()

	select {
	case <-ctx.Done():
		log.Print(ctx.Err())
		exit = 1
	case <-cmdctx.Done():
		if cmdErr != nil {
			log.Print(cmdErr)
			exit = 2
		}
	}
	cleanup.Wait()
}
