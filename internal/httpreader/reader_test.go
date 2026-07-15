package httpreader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"testing/quick"
	"time"

	"github.com/quay/claircore/test"
)

var tKey = &struct{}{}

type compliantServer struct {
	f   *os.File
	sz  int64
	mod time.Time
}

func (s *compliantServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set(`Allow`, http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set(`Content-Type`, `application/octet-stream`)
	// SectionReader trick to get multiple independent cursors into the file.
	content := io.NewSectionReader(s.f, 0, s.sz)
	http.ServeContent(w, r, "randfile", s.mod, content)
}

func fileserver(t testing.TB, name string) *compliantServer {
	var err error
	srv := new(compliantServer)
	srv.f, err = os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := srv.f.Close(); err != nil {
			t.Error(err)
		}
	})
	fi, err := srv.f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	srv.sz = fi.Size()
	srv.mod = test.Modtime(t, name)
	return srv
}

// NoLengthServer is a cut-rate implementation of a byte-range aware server.
//
// It does most of the "normal" work, but strenuously avoids noticing the resource's length.
type noLengthServer struct {
	zero *os.File
	size int64
	prev int64
}

func newNoLength(t *testing.T, size int64) *noLengthServer {
	zero, err := os.Open("/dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := zero.Close(); err != nil {
			t.Log(err)
		}
	})
	return &noLengthServer{
		size: size,
		zero: zero,
	}
}

func (s *noLengthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := ctx.Value(tKey).(*testing.T)
	if r.Method != http.MethodGet {
		panic("unexpected method: " + r.Method)
	}
	br := r.Header.Get("range")
	w.Header().Set("accept-ranges", "bytes")
	var b strings.Builder
	defer func() {
		if b.Len() > 0 {
			t.Log(b.String())
		}
	}()
	switch {
	case br == `bytes=-1`:
		// Trigger our dumb behavior.
		if _, err := io.Copy(w, io.LimitReader(s.zero, s.size)); err != nil {
			t.Logf("expected error writing last byte: %v", err)
		}
	case br == "":
		panic("no range")
	case !strings.HasPrefix(br, `bytes=`):
		panic("non-bytes range: " + br)
	default:
		_, req, ok := strings.Cut(br, "=")
		if !ok {
			panic("weird range: " + br)
		}
		firstStr, lastStr, ok := strings.Cut(req, "-")
		if !ok {
			panic("weird range: " + br)
		}
		first, _ := strconv.ParseInt(firstStr, 10, 64)
		reqLast, _ := strconv.ParseInt(lastStr, 10, 64)
		fmt.Fprintf(&b, "req: %s, len: %d, ", req, (reqLast+1)-first)
		if first >= s.size {
			b.WriteString("serving: 0")
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if first == s.prev {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.prev = first
		last := min(reqLast, s.size-1)
		fmt.Fprintf(&b, "serving: %d", (last+1)-first)
		w.Header().Set("content-range", fmt.Sprintf("bytes %d-%d/*", first, last))
		w.WriteHeader(http.StatusPartialContent)
		if n, err := io.Copy(w, io.LimitReader(s.zero, (last+1)-first)); err != nil && n != 0 {
			t.Error(err)
		}
	}
}

func TestCompliant(t *testing.T) {
	t.Parallel()
	randfile := ensureRandfile(t)

	ctx := test.Logging(t)
	h := fileserver(t, randfile)
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context {
		return context.WithValue(ctx, tKey, t)
	}
	srv.Start()
	t.Cleanup(srv.Close)
	rd, err := New(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	f, err := os.Open(randfile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := quick.Check(checkEq(t, f, rd), &eqConfig); err != nil {
		t.Error(err)
	}
}

func TestLengthSearch(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

	doSearch := func(sz int64) bool {
		srv := httptest.NewUnstartedServer(newNoLength(t, sz))
		srv.Config.BaseContext = func(_ net.Listener) context.Context {
			return context.WithValue(ctx, tKey, t)
		}
		srv.Start()
		defer srv.Close()
		rd, err := New(ctx, srv.Client(), srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()

		got, want := rd.Size(), sz
		if got != want {
			t.Logf("got: %d (%d MiB), want: %d (%d MiB)", got, got/(1<<20), want, want/(1<<20))
			return false
		}
		return true
	}

	if err := quick.Check(doSearch, &quick.Config{
		MaxCount:      10,
		MaxCountScale: 5,
		Values: func(args []reflect.Value, rng *rand.Rand) {
			const max = 10240
			sz := rng.Int63n(max) + 1 // Make this [1, max]
			args[0] = reflect.ValueOf((1 << 20) * sz)
		},
	}); err != nil {
		t.Error(err)
	}
}

func TestMulti(t *testing.T) {
	t.Parallel()
	randfile := ensureRandfile(t)
	ctx := test.Logging(t)
	h := fileserver(t, randfile)
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context {
		return context.WithValue(ctx, tKey, t)
	}
	srv.Start()
	t.Cleanup(srv.Close)
	rd, err := New(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	cfg := eqConfig
	cfg.MaxCount = 4

	for range 4 {
		wg.Add(1)
		f, err := os.Open(randfile)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		go func() {
			defer wg.Done()
			<-start
			if err := quick.Check(checkEq(t, f, rd), &cfg); err != nil {
				t.Error(err)
			}
		}()
	}

	close(start)
	wg.Wait()
}

const randfileSz = (1 << 20) * 50

var (
	randfilePath string
	randfileOnce sync.Once
)

func ensureRandfile(t testing.TB) string {
	randfileOnce.Do(func() {
		stamp := test.Modtime(t, ".")
		randfilePath = test.GenerateFixture(t, "randfile", stamp, genRandfile)
	})
	if t.Failed() {
		return ""
	}
	return randfilePath
}

func genRandfile(t testing.TB, f *os.File) {
	defer f.Close()
	s := rand.NewSource(660096000)
	rng := rand.New(s)
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadFrom(io.LimitReader(rng, randfileSz)); err != nil {
		t.Fatal(err)
	}
}

func checkEq(t *testing.T, f *os.File, rd *Reader) func(int64, int64) bool {
	var ct atomic.Int64
	t.Helper()
	t.Cleanup(func() {
		t.Logf("ran %d times", ct.Load())
	})
	return func(sz, off int64) bool {
		ct.Add(1)
		// Read our want value:
		var want bytes.Buffer
		r := io.NewSectionReader(f, off, sz)
		if _, err := io.Copy(&want, r); err != nil {
			t.Error(err)
			return false
		}
		t.Logf("read %d bytes at offset %d", sz, off)

		// Read our got value:
		r = io.NewSectionReader(rd, off, sz)
		if err := iotest.TestReader(r, want.Bytes()); err != nil {
			t.Error(err)
			return false
		}
		return true
	}
}

var eqConfig = quick.Config{
	MaxCount:      10,
	MaxCountScale: 5,
	Values: func(args []reflect.Value, rng *rand.Rand) {
		const max = 8192
		sz := rng.Int63n(max) + 1 // Make this [1, max]
		args[0] = reflect.ValueOf(sz)
		args[1] = reflect.ValueOf(rng.Int63n(randfileSz)) // Offset
	},
}
