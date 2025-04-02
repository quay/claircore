// Fetch-container-rpm-manifest is a tool to fetch RPM manifests for Red Hat
// containers matching provided patterns.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/txtar"
)

const (
	exeName    = `fetch-container-rpm-manifest`
	levelTrace = slog.LevelDebug - 4

	usageFmt = `Usage of %[1]s:

        %[1]s [OPTIONS] search_expr...

OPTIONS:

%[2]s
ARGUMENTS:

  search_expr   search expression for repositories
                The query language is probably Lucene, so glob(7) operators
                should work.

Results are returned in txtar format on stdout. If multiple search expressions
are provided, the resulting txtars are separated by a ␜ (0x1C).
`
)

func main() {
	var err error
	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

	ctx := context.Background()
	ctx, done := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer done()
	var logLevel slog.LevelVar
	output := os.Stdout
	set := flag.CommandLine
	set.BoolFunc("D", "debug output (multiple times for more)", func(_ string) error {
		logLevel.Set(logLevel.Level() - 4)
		return nil
	})
	set.Func("o", "write output to `file` (default stdout)", func(p string) error {
		if err := output.Close(); err != nil {
			return err
		}
		var err error
		output, err = os.Create(p)
		if err != nil {
			return err
		}
		return nil
	})
	set.Usage = func() {
		var buf bytes.Buffer
		set.SetOutput(&buf)
		set.PrintDefaults()
		fmt.Fprintf(os.Stderr, usageFmt, exeName, buf.String())
	}
	flag.Parse()

	if set.NArg() == 0 {
		err = errors.New("need at least one repository search term")
		set.Usage()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, err)
		return
	}

	slog.SetDefault(
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: &logLevel,
		})))

	err = Main(ctx, output, set.Args())
}

// Main is the entrypoint for search.
func Main(ctx context.Context, out io.Writer, qs []string) error {
	c := &http.Client{}
	hc := &HydraClient{c}
	cc := &CatalogClient{c}
	runTime := time.Now()
	var toolVer string
	if bi, ok := debug.ReadBuildInfo(); ok {
		toolVer = bi.Main.Version
	}

	eg, ctx := errgroup.WithContext(ctx)
	var wg sync.WaitGroup
	wg.Add(len(qs))
	output := make(chan *txtar.Archive, runtime.GOMAXPROCS(0))

	// Output goroutine
	eg.Go(func() error {
		first := true
		for src := range output {
			if !first {
				io.WriteString(out, "\x1C") // write ␜ if outputting multiple txtars
			}
			_, err := io.Copy(out, bytes.NewReader(txtar.Format(src)))
			if err != nil {
				slog.ErrorContext(ctx, "archive write error", "reason", err)
				return err
			}
			first = false
		}
		return nil
	})
	// Cleanup goroutine
	eg.Go(func() error {
		wg.Wait()
		close(output)
		return nil
	})
	for _, q := range qs {
		q := "repository:" + q
		// Worker goroutine
		eg.Go(func() error {
			defer wg.Done()
			ar := new(txtar.Archive)
			WriteHeader(ar, "generator", "fetch-container-rpm-manifest")
			WriteHeader(ar, "version", toolVer)
			WriteHeader(ar, "created", runTime.Format(time.RFC3339))

			slog.DebugContext(ctx, "beginning search", "query", q)
			docs, err := hc.Search(ctx, ar, q)
			if err != nil {
				slog.ErrorContext(ctx, "search error", "reason", err)
				return err
			}

			for _, doc := range docs {
				slog.DebugContext(ctx, "found repository", "name", doc.Repository)
				err := cc.FetchManifest(ctx, ar, doc.ID)
				if err != nil {
					slog.ErrorContext(ctx, "manifest fetch error", "reason", err)
					return err
				}
			}

			ar.Comment = fmt.Appendln(ar.Comment)
			select {
			case output <- ar:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
			return nil
		})
	}

	return eg.Wait()
}

// WriteHeader writes a MIME header to the comment of "ar".
func WriteHeader(ar *txtar.Archive, key, value string) {
	ar.Comment = fmt.Append(ar.Comment,
		textproto.CanonicalMIMEHeaderKey(key), ": ", value, "\n")
}

// DecodeJSON does what it says on the tin.
func DecodeJSON[T any](r io.Reader) (*T, error) {
	var tgt T
	err := json.NewDecoder(r).Decode(&tgt)
	if err != nil {
		return nil, err
	}
	return &tgt, nil
}

// TeeJSONRequest makes a "GET" request to URL "u" via "c", recording the URL
// and response in "ar". The response is decoded into a value of type T and
// returned.
func TeeJSONRequest[T any](ctx context.Context, c *http.Client, ar *txtar.Archive, u *url.URL) (*T, error) {
	slog.Log(ctx, levelTrace, "http request attempt", "url", u)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected response: %s", u.String(), res.Status)
	}
	slog.Log(ctx, levelTrace, "http request success", "url", u, "status", res.Status)
	WriteHeader(ar, "url", u.String())

	buf := getBuf()
	defer func() {
		defer putBuf(buf)
		// Need a non-pooled destination, lest the buffer get recycled before
		// the archive is rendered.
		dst := new(bytes.Buffer)
		dst.Grow(buf.Len())
		json.Compact(dst, buf.Bytes())
		slog.Log(ctx, levelTrace, "compacted JSON",
			"in_bytes", buf.Len(),
			"out_bytes", dst.Len())
		ar.Files = append(ar.Files, txtar.File{
			Name: path.Join(u.Hostname(), u.EscapedPath()),
			Data: dst.Bytes(),
		})
	}()
	return DecodeJSON[T](io.TeeReader(res.Body, buf))
}

var bufPool sync.Pool

func getBuf() *bytes.Buffer {
	v := bufPool.Get()
	if v == nil {
		return new(bytes.Buffer)
	}
	return v.(*bytes.Buffer)
}

func putBuf(b *bytes.Buffer) {
	if b.Cap() > 8<<20 {
		return
	}
	b.Reset()
	bufPool.Put(b)
}
