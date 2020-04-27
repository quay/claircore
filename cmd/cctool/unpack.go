package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/quay/claircore/internal/indexer/fetcher"
)

type unpackConfig struct {
	timeout time.Duration
}

// Unpack will decompress and untar each layer of the provided image ref
func Unpack(cmd context.Context, cfg *commonConfig, args []string) error {
	cmdcfg := unpackConfig{}
	fs := flag.NewFlagSet("cctool unpack", flag.ExitOnError)
	fs.DurationVar(&cmdcfg.timeout, "timeout", 5*time.Minute, "timeout for successful http responses")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "\tcctool unpack <image-ref>\n")
		fmt.Fprintf(out, "Arguments:\n")
		fmt.Fprintf(out, "\timage-ref: a reference to an image and its repository\n\n")
	}
	fs.Parse(args)

	// get the image reference from argument.
	if len(fs.Args()) <= 0 || len(fs.Args()) >= 2 {
		fs.Usage()
		return nil
	}

	image := fs.Args()[0]
	ctx, done := context.WithTimeout(cmd, cmdcfg.timeout)
	defer done()

	// inspect image reference and get manifest
	m, err := Inspect(ctx, image)
	if err != nil {
		return err
	}

	// signal to main cli we need to wait on cleanup
	// we are about to write to the file system
	cfg.cleanup.Add(1)

	// fetch layers
	ctx, done = context.WithTimeout(cmd, cmdcfg.timeout)
	defer done()

	log.Printf("fetching layers")
	f := fetcher.New(nil, "")
	err = f.Fetch(ctx, m.Layers)
	if err != nil {
		return err
	}
	log.Printf("successfully fetched layers")

	// create a tmp dir we will unpack layers to
	td, err := ioutil.TempDir("", "cctool-unpack-")

	log.Printf("exacting layers into tmp dir: %v.", td)
	for i, layer := range m.Layers {
		dirName := layer.Hash.String()
		dir := filepath.Join(td, strconv.Itoa(i)+"-"+dirName)
		err := os.Mkdir(dir, 0755)
		if err != nil {
			return err
		}

		errbuf := bytes.Buffer{}
		rd, err := layer.Reader()
		if err != nil {
			return err
		}
		tarcmd := exec.CommandContext(ctx, "tar", "-xC", dir)
		tarcmd.Stdin = rd
		tarcmd.Stderr = &errbuf
		if err := tarcmd.Run(); err != nil {
			return fmt.Errorf("err: %v stderr: %v", err, errbuf.String())
		}

		// add u+w to all files so we do not error deleting files written
		// without the w bit by tar
		chmodcmd := exec.CommandContext(ctx, "chmod", "-R", "u+w", dir)
		errbuf.Reset()
		chmodcmd.Stderr = &errbuf
		if err := chmodcmd.Run(); err != nil {
			return fmt.Errorf("err: %v stderr: %v", err, errbuf.String())
		}
	}

	// defer cleanup
	defer func() {
		log.Printf("recurively deleting tmp dir %v", td)
		err := os.RemoveAll(td)
		if err != nil {
			log.Printf("failed to recursively remove %v: %v", td, err)
		}
		log.Printf("deleting downloaded layers in tmp dir")
		err = f.Close()
		if err != nil {
			log.Printf("failed to clean layer files in tmp directory: %v", err)
		}
		// signal to main cli routine cleanup is done
		cleanup.Done()
	}()

	// input loop waiting for exit
	log.Printf(`you may now inspect layers. type "exit" or ctrl-c + enter to cleanup and quit`)
	input := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for input.Scan() {
		w := input.Text()
		switch {
		case w == "exit":
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			log.Printf(`type "exit" or ctrl-c + enter to cleanup and quit`)
			fmt.Print("> ")
		}
	}
	panic("not reachable")
}
