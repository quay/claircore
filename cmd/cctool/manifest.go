package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type manifestConfig struct {
	timeout time.Duration
	pretty  bool
}

// Manifest is the subcommand for generating container manifests.
func Manifest(cmd context.Context, cfg *commonConfig, args []string) error {
	cmdcfg := manifestConfig{}
	fs := flag.NewFlagSet("cctool manifest", flag.ExitOnError)
	fs.DurationVar(&cmdcfg.timeout, "timeout", 5*time.Minute, "timeout for successful http responses")
	fs.Parse(args)

	images := fs.Args()
	if len(images) == 0 {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			images = append(images, strings.TrimSpace(s.Text()))
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)

	ctx, done := context.WithTimeout(cmd, cmdcfg.timeout)
	defer done()
	var errd bool
	errs := make([]error, len(images))
	var eo sync.Once
	var wg sync.WaitGroup
	wg.Add(len(images))
	for i, img := range images {
		img := img
		i := i
		go func() {
			defer wg.Done()
			m, err := Inspect(ctx, img)
			if err != nil {
				eo.Do(func() { errd = true })
				errs[i] = err
				return
			}
			if err := enc.Encode(m); err != nil {
				eo.Do(func() { errd = true })
				errs[i] = err
				return
			}
		}()
	}
	wg.Wait()
	if errd {
		buf := &bytes.Buffer{}
		for _, err := range errs {
			if err != nil {
				fmt.Fprintln(buf, err)
			}
		}
		return errors.New(buf.String())
	}
	return nil
}
