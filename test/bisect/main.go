// Bisect is a git bisect helper.
//
// It relies on some makefile targets to spin up and down all services and wraps
// calls to cctool.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sync/errgroup"
)

var V io.Writer = ioutil.Discard

func main() {
	var exit int
	defer func() {
		if exit != 0 {
			os.Exit(exit)
		}
	}()
	targetUp := flag.String("target-up", "podman-dev-up", "makefile target to bring up local services")
	targetDown := flag.String("target-down", "podman-dev-down", "makefile target to bring down local services")
	timeoutUp := flag.Duration("timeout-up", 5*time.Minute, "timeout for services to come up")
	timeoutTest := flag.Duration("timeout-test", 5*time.Minute, "timeout for cctool tests")
	verbose := flag.Bool("v", false, "enable verbose output")
	flag.Parse()

	if *verbose {
		V = os.Stderr
		defer os.Stderr.Sync()
	}

	ctx := interrupt(context.Background())
	ctx, done := context.WithCancel(ctx)

	imgs := flag.Args()
	fmt.Printf("testing: %v\n", imgs)

	defer func() {
		if err := setupCmd(context.Background(), nil, nil, "make", *targetDown).Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			exit = 1
		}
	}()

	if err := setupCmd(ctx, nil, nil, "go", "mod", "vendor").Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit = 1
		return
	}

	if err := setupCmd(ctx, nil, nil, "make", *targetUp).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit = 1
		return
	}

	var toolPath string

	tctx, cancel := context.WithTimeout(ctx, *timeoutUp)
	defer cancel()
	eg, gctx := errgroup.WithContext(tctx)
	eg.Go(checkURL(gctx, `http://localhost:8080/`))
	eg.Go(checkURL(gctx, `http://localhost:8081/`))
	eg.Go(func() error {
		var err error
		toolPath, err = buildTool(ctx)
		return err
	})
	if err := eg.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit = 1
		return
	}

	tctx, cancel = context.WithTimeout(ctx, *timeoutTest)
	defer cancel()
	eg, gctx = errgroup.WithContext(tctx)
	for _, img := range imgs {
		eg.Go(runTool(gctx, toolPath, img))
	}
	if err := eg.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit = 1
		return
	}

	done()
}

func setupCmd(ctx context.Context, stdout, stderr io.Writer, exe string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdout = os.Stdout
	if stdout != nil {
		cmd.Stdout = io.MultiWriter(stdout, os.Stdout)
	}
	cmd.Stderr = os.Stderr
	if stderr != nil {
		cmd.Stderr = io.MultiWriter(stderr, os.Stderr)
	}
	fmt.Fprintf(V, "command: %q\n", cmd.Args)
	return cmd
}

func buildTool(ctx context.Context) (string, error) {
	f, err := ioutil.TempFile("", "cctool.")
	if err != nil {
		return "", err
	}
	exe := f.Name()
	go func() {
		<-ctx.Done()
		os.Remove(exe)
	}()
	if err := f.Close(); err != nil {
		return "", err
	}
	cmd := setupCmd(ctx, nil, nil, "go", "build", "-o", exe, "./cmd/cctool")
	if err := cmd.Run(); err != nil {
		return "", err
	}
	fmt.Fprintf(V, "%s: built\n", exe)
	return exe, nil
}

func runTool(ctx context.Context, exe, img string) func() error {
	buf := &bytes.Buffer{}
	cmd := setupCmd(ctx, buf, nil, exe, `report`, img)
	return func() error {
		if err := cmd.Run(); err != nil {
			return err
		}
		if bytes.Count(buf.Bytes(), []byte{'\n'}) < 2 {
			return fmt.Errorf("!!! %q failed to index+match successfully", img)
		}
		return nil
	}
}

func interrupt(ctx context.Context) context.Context {
	ctx, done := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	go func() {
		for range ch {
			done()
		}
	}()
	return ctx
}

func checkURL(ctx context.Context, u string) func() error {
	return func() error {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return err
			}
			res, err := http.DefaultClient.Do(req)
			if res != nil {
				res.Body.Close()
			}
			if err != nil {
				continue
			}
			if res.StatusCode == http.StatusNotFound {
				fmt.Fprintf(V, "%s: ok\n", u)
				return nil
			}
		}
	}
}
