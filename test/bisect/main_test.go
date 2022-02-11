package main_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/test/integration"
	_ "github.com/quay/claircore/updater/defaults"
)

var (
	run          bool
	stderr       bool
	dumpManifest string
	dumpIndex    string
	dumpReport   string
)

var (
	manifestFilename = template.New("manifest")
	indexFilename    = template.New("index")
	reportFilename   = template.New("report")
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	flag.BoolVar(&run, "enable", false, "enable the bisect test")
	flag.BoolVar(&stderr, "stderr", false, "dump logs to stderr")
	flag.StringVar(&dumpManifest, "dump-manifest", "", "dump manifest to templated location, if provided")
	flag.StringVar(&dumpIndex, "dump-index", "", "dump index to templated location, if provided")
	flag.StringVar(&dumpReport, "dump-report", "", "dump report to templated location, if provided")
	flag.Parse()
	defer integration.DBSetup()()
	c = m.Run()
}

func TestRun(t *testing.T) {
	if !run {
		t.Skip("skipping bisect tool run")
	}
	integration.NeedDB(t)
	ctx := context.Background()
	layersDir, err := filepath.Abs(`testdata/layers`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, srv := setup(ctx, t, layersDir)

	indexer := mkIndexer(ctx, t, srv.Client())
	matcher := mkMatcher(ctx, t, srv.Client())
	if err := waitForInit(ctx, matcher); err != nil {
		t.Fatal(err)
	}

	var done context.CancelFunc
	var tctx context.Context
	if d, ok := t.Deadline(); ok {
		tctx, done = context.WithDeadline(ctx, d.Add(-5*time.Second))
	} else {
		to := 20 * time.Minute
		fmt.Fprintln(os.Stderr, "no timeout provided, setting to ", to)
		tctx, done = context.WithTimeout(ctx, to)
	}
	defer done()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, `no images provided, running until timeout`)
		<-tctx.Done()
		return
	}

	eg, ctx := errgroup.WithContext(tctx)
	for _, img := range flag.Args() {
		eg.Go(runOne(ctx, indexer, matcher, layersDir, srv.URL, img))
	}
	if err := eg.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		t.Error(err)
	}
}

// RunOne the function returned runs an image "n" through the indexer and
// matcher.
//
// The results are written in a text format to stdout.
func runOne(ctx context.Context, indexer *libindex.Libindex, matcher *libvuln.Libvuln, root, url, n string) func() error {
	h := fnv.New64a()
	fmt.Fprint(h, n)
	prefix := fmt.Sprintf("%x", h.Sum(nil))
	workdir := filepath.Join(root, prefix)
	return func() error {
		var err error
		_, stat := os.Stat(workdir)
		if errors.Is(stat, os.ErrNotExist) {
			cmd := exec.CommandContext(ctx, `skopeo`, `copy`, `docker://`+n, `dir:`+workdir)
			err = cmd.Run()
		}
		if err != nil {
			return err
		}
		f, err := os.Open(filepath.Join(workdir, `manifest.json`))
		if err != nil {
			return err
		}
		defer f.Close()
		var rm regManifest
		if err := json.NewDecoder(f).Decode(&rm); err != nil {
			return err
		}
		m := rm.Manifest(url + `/` + prefix)
		if err := writeOut(manifestFilename, n, &m); err != nil {
			return err
		}

		ir, err := indexer.Index(ctx, &m)
		if err != nil {
			return err
		}
		if err := writeOut(indexFilename, n, ir); err != nil {
			return err
		}

		vr, err := matcher.Scan(ctx, ir)
		if err != nil {
			return err
		}
		if err := writeOut(reportFilename, n, vr); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		defer tw.Flush()
		pkgs := make([]string, 0, len(vr.Packages))
		for pkg := range vr.Packages {
			pkgs = append(pkgs, pkg)
		}
		sort.Strings(pkgs)
		for _, pid := range pkgs {
			vs, ok := vr.PackageVulnerabilities[pid]
			if !ok {
				continue
			}
			pkg := vr.Packages[pid]
			for _, id := range vs {
				v := vr.Vulnerabilities[id]
				fmt.Fprintf(tw, "%s\t%s\t%s\n", n, pkg.Name, v.Name)
			}
		}
		return nil
	}
}

// RegManifest is a helper to go from a registry's manifest to a claircore
// manifest.
type regManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []regLayer `json:"layers"`
}

// Manifest returns a claircore Manifest derived from the regManifest, assuming
// that layers can be downloaded by their digest if appended to "url".
func (r *regManifest) Manifest(url string) (m claircore.Manifest) {
	m.Hash = claircore.MustParseDigest(r.Config.Digest)
	for _, l := range r.Layers {
		m.Layers = append(m.Layers, &claircore.Layer{
			Hash:    claircore.MustParseDigest(l.Digest),
			URI:     url + `/` + l.Digest,
			Headers: make(map[string][]string),
		})
	}
	return m
}

// RegLayer is a helper to go from a registry's manifest to a claircore
// manifest.
type regLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// EscapeImage makes a name safer for filesystem use.
func escapeImage(i string) string {
	return strings.ReplaceAll(i, string(filepath.Separator), "-")
}

// Setup does a grip of test setup work, returning a context that will cancel on
// interrupt and a server set up to serve files from "dir".
func setup(ctx context.Context, t *testing.T, dir string) (context.Context, *httptest.Server) {
	l := zerolog.Nop()
	if stderr {
		l = zerolog.New(zerolog.NewConsoleWriter())
	}
	zlog.Set(&l)

	for _, v := range []struct {
		Tmpl **template.Template
		In   string
	}{
		{Tmpl: &manifestFilename, In: dumpManifest},
		{Tmpl: &indexFilename, In: dumpIndex},
		{Tmpl: &reportFilename, In: dumpReport},
	} {
		if v.In == "" {
			*v.Tmpl = nil
			continue
		}
		if _, err := (*v.Tmpl).Parse(v.In); err != nil {
			t.Error(err)
		}
	}

	ctx, done := signal.NotifyContext(ctx, os.Interrupt)
	t.Cleanup(done)

	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fsrv := http.FileServer(http.Dir(dir))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.Path)
		b := path.Base(r.URL.Path)
		if strings.Contains(b, ":") {
			n, err := r.URL.Parse(b[strings.IndexByte(b, ':')+1:])
			if err != nil {
				t.Logf("url weirdness: %v", err)
			} else {
				r.URL = n
			}
		}
		fsrv.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	return ctx, srv
}

// MkIndexer constructs an indexer and associates its cleanup with "t".
func mkIndexer(ctx context.Context, t *testing.T, c *http.Client) *libindex.Libindex {
	db := integration.NewPersistentDB(ctx, t, "indexer_bisect")
	pool, err := postgres.Connect(ctx, db.String(), "indexer_bisect")
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.InitPostgresIndexerStore(ctx, pool, true)
	if err != nil {
		t.Fatal(err)
	}
	opts := libindex.Options{
		Store: store,
	}
	i, err := libindex.New(ctx, &opts, c)
	if err != nil {
		db.Close(ctx, t)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close(ctx, t)
		if err := i.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return i
}

// MkMatcher constructs a matcher and associates its cleanup with "t".
func mkMatcher(ctx context.Context, t *testing.T, c *http.Client) *libvuln.Libvuln {
	db := integration.NewPersistentDB(ctx, t, "matcher_bisect")
	pool, err := postgres.Connect(ctx, db.String(), "matcher_bisect")
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.InitPostgresMatcherStore(ctx, pool, true)
	if err != nil {
		t.Fatal(err)
	}
	opts := libvuln.Options{
		Store:  store,
		Client: c,
	}
	m, err := libvuln.New(ctx, &opts)
	if err != nil {
		db.Close(ctx, t)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close(ctx, t)
		if err := m.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return m
}

// WaitForInit waits until the *Libvuln reports true for an Initialized call or
// the passed Context times out.
func waitForInit(ctx context.Context, m *libvuln.Libvuln) error {
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for ok, err := m.Initialized(ctx); ; ok, err = m.Initialized(ctx) {
		if err != nil {
			return err
		}
		if ok {
			break
		}
		fmt.Fprintln(os.Stderr, "waiting")
		select {
		case <-timer.C:
			continue
		case <-ctx.Done():
			return err
		}
	}
	return nil
}

// WriteOut runs the template "tmpl" with "name" as an input, then encodes "v"
// as JSON and writes it into the file named by the template output.
//
// If "tmpl" is nil, the function returns nil immediately.
func writeOut(tmpl *template.Template, name string, v interface{}) error {
	if tmpl == nil {
		return nil
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, escapeImage(name)); err != nil {
		return err
	}
	f, err := os.Create(buf.String())
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(v); err != nil {
		return err
	}
	return nil
}
