package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/quay/claircore/internal/mdbook"
	"github.com/quay/claircore/internal/mdbook/godoc"
	"github.com/quay/claircore/internal/mdbook/injecturls"
	"github.com/quay/claircore/internal/mdbook/maketarget"
	"github.com/quay/claircore/internal/mdbook/mermaid"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix(filepath.Base(os.Args[0]) + ": ")
	flag.Usage = usage
	flag.Parse()
	args(flag.Args())
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	err := run(ctx, os.Stdin, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}

// Run reads the mdbook context from "r", runs all registered hooks, and writes
// to "w" on success.
func run(ctx context.Context, r io.Reader, w io.Writer) error {
	cfg, book, err := mdbook.Decode(r)
	if err != nil {
		return err
	}
	proc, err := mdbook.NewProc(ctx, cfg,
		godoc.Register,
		injecturls.Register,
		maketarget.Register,
		mermaid.Register,
	)
	if err != nil {
		return err
	}

	if err := proc.Walk(ctx, book); err != nil {
		return err
	}

	if err := json.NewEncoder(w).Encode(&book); err != nil {
		return err
	}
	return nil
}

// args implements handling the expected CLI arguments.
//
// This function calls [os.Exit] under the right circumstances.
func args(argv []string) {
	// Handle when called with "supports $renderer".
	if len(argv) != 2 {
		return
	}
	switch argv[0] {
	case "help":
		flag.Usage()
		os.Exit(2)
	case "supports":
		switch argv[1] {
		case "html":
		default:
			log.Printf("unsupported renderer: %q", argv[1])
			os.Exit(2)
		}
	default:
		log.Printf("unknown subcommand: %q", argv[0])
		os.Exit(2)
	}
	os.Exit(0)
}

func usage() {
	out := flag.CommandLine.Output()
	cmd := filepath.Base(os.Args[0])
	fmt.Fprintf(out, "Usage of %s:\n", cmd)
	fmt.Fprintf(out, "\t%s supports html\n", cmd)
	flag.PrintDefaults()
}
