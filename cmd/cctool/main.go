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
)

var cleanup sync.WaitGroup

type commonConfig struct {
	cleanup *sync.WaitGroup
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

	var cfg commonConfig = commonConfig{
		cleanup: &cleanup,
	}
	fs := flag.NewFlagSet("main", flag.ExitOnError)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage of %s:\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nSubcommands\n\n")
		fmt.Fprintln(out, "report")
		fmt.Fprintln(out, "\tgenerate reports for containers provided as arguments or on stdin")
		fmt.Fprintln(out, "manifest")
		fmt.Fprintln(out, "\tgenerate manifests for containers provided as arguments or on stdin")
		fmt.Fprintln(out, "unpack")
		fmt.Fprintln(out, "\textracts each container's layers content for inspection")
		fmt.Fprintln(out)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	var cmd subcmd
	switch n := fs.Arg(0); n {
	case "report":
		cmd = Report
	case "manifest":
		cmd = Manifest
	case "unpack":
		cmd = Unpack
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
