package test

import (
	"bufio"
	"bytes"
	stdcmp "cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	mock_datastore "github.com/quay/claircore/test/mock/datastore"
)

// MatcherGetCall describes one call to a [datastore.Vulnerabilities.Get]
// method.
type MatcherGetCall struct {
	Vulnerabilities map[string][]*claircore.Vulnerability `json:"vulnerabilities"`
	Error           string                                `json:"error"`
	Records         []*claircore.IndexRecord              `json:"records"`
}

// RunMatcherTests tests provided [driver.Matcher] implementations using all
// [txtar.Archive] files matching the glob "*.txtar" in "dir".
//
// Each file defines a subtest and must contain the needed fixtures.
//
// Needed files in an archive are:
//   - Want: a [claircore.VulnerabilityReport] in JSON format
//   - IndexReport: a [claircore.IndexReport] in JSON format
//   - Database: "application/json-seq" formatted [MatcherGetCall] objects
//
// The file comment can control the behavior of the test via headers:
//   - Error: if "OK", the test will expect an error return
//
// All the loaded files support a limited [JsonRef] syntax: "file:<name>" will
// load "<name>" from the archive.
//
// [Jq] has the "--seq" flag to help creating json-seq files.
//
// [JsonRef]: http://jsonref.org/
// [Jq]: https://jqlang.github.io/jq/
func RunMatcherTests(ctx context.Context, t *testing.T, dir string, matchers ...driver.Matcher) {
	t.Helper()
	if ctx == nil {
		ctx = zlog.Test(context.Background(), t)
	}

	ms, err := filepath.Glob(filepath.Join(dir, "*.txtar"))
	if err != nil {
		t.Fatalf("bad glob: %v", err)
	}
	ctrl := gomock.NewController(t)
	store := mock_datastore.NewMockVulnerability(ctrl)

	for _, m := range ms {
		n := filepath.Base(m)
		n = strings.TrimSuffix(n, filepath.Ext(n))
		t.Run(n, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			t.Logf("loading txtar: %#q", m)

			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatalf("opening txtar: %v", err)
			}
			sys, err := txtar.FS(ar)
			if err != nil {
				t.Fatalf("opening txtar FS: %v", err)
			}
			tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(ar.Comment)))
			hdr, err := tp.ReadMIMEHeader()
			if err != nil && err != io.EOF {
				t.Errorf("reading headers: %v", err)
			}

			errOK := slices.ContainsFunc(hdr.Values("Error"), func(k string) bool {
				return strings.ToUpper(k) == "OK"
			})
			index := loadJSONFile[claircore.IndexReport](t, sys, "IndexReport")
			want := loadJSONFile[claircore.VulnerabilityReport](t, sys, "Want")
			loadDatastoreVulnerabilityMock(t, sys, store, "Database")

			got, err := matcher.Match(ctx, index, matchers, store)
			switch {
			case err == nil:
			case errOK:
				t.Logf("expected error: %v", err)
				return
			default:
				t.Errorf("unexpected error: %v", err)
			}
			t.Logf("vulnerabilities found: %d", len(got.Vulnerabilities))
			if !cmp.Equal(got, want, CmpOptions) {
				t.Error(cmp.Diff(got, want, CmpOptions))
			}
		})
	}
}

func loadJSONFile[T any](t testing.TB, sys fs.FS, p string) *T {
	t.Helper()
	data, err := fs.ReadFile(sys, p)
	if err != nil {
		t.Errorf("failed to decode %q: %v", p, err)
		return nil
	}
	v, err := loadJSON[T](t, sys, data)
	if err != nil {
		t.Errorf("failed to decode %q: %v", p, err)
		return nil
	}
	return v
}

func loadDatastoreVulnerabilityMock(t testing.TB, sys fs.FS, mock *mock_datastore.MockVulnerability, name string) {
	t.Helper()

	f, err := sys.Open(name)
	if err != nil {
		t.Fatalf("failed to open %q: %v", name, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("closing %q: %v", name, err)
		}
	}()
	s := bufio.NewScanner(f)
	s.Split(SplitJSONSeq)
	defer func() {
		if err := s.Err(); err != nil {
			t.Errorf("loading MatcherGetCalls: %v", err)
		}
	}()
	for i := 0; s.Scan(); i++ {
		call, err := loadJSON[MatcherGetCall](t, sys, s.Bytes())
		if err != nil {
			t.Fatalf("reading database mock #%02d: %v", i, err)
		}
		records := func(in any) bool {
			got := in.([]*claircore.IndexRecord)
			slices.SortFunc(got, cmpIndexRecord)
			want := call.Records
			slices.SortFunc(want, cmpIndexRecord)
			ok := cmp.Equal(got, want)
			// Uncomment below if you're not sure why the args aren't matching:
			// if !ok {
			// 	t.Logf("call #02d: mismatch:\n%s", cmp.Diff(got, want))
			// }
			return ok
		}

		mock.EXPECT().
			Get(gomock.AssignableToTypeOf(ctxType), gomock.Cond(records), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []*claircore.IndexRecord, _ datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
				if call.Error != "" {
					t.Logf("call #%02d: marked as error: %v", i, err)
					return nil, errors.New(call.Error)
				}
				t.Logf("call #%02d: returning %d vulnerabilities", i, len(call.Vulnerabilities))
				return call.Vulnerabilities, nil
			})
	}
}

var ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()

func cmpIndexRecord(a, b *claircore.IndexRecord) int {
	return stdcmp.Compare(a.Package.ID, b.Package.ID)
}

// SplitJSONSeq is a [bufio.SplitFunc] that splits "application/json-seq"
// streams.
func SplitJSONSeq(data []byte, atEOF bool) (advance int, token []byte, err error) {
	intra := []byte{'\n', '\x1e'}
	if data[0] != intra[1] {
		return 0, nil, fmt.Errorf("format botch: expected %q, found %q", intra[1], data[0])
	}
	token = data[1:]
	idx := bytes.Index(token, intra)
	switch {
	case idx == -1 && atEOF:
		return len(data), bytes.TrimSpace(token), bufio.ErrFinalToken
	case idx == -1:
		return 0, nil, nil // Need more data
	}
	token = token[:idx]
	return len(token) + 2, token, nil
}
