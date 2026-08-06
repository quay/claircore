package postgres

import (
	"bytes"
	"crypto/md5"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test"
)

// This is a copy of the current implementation as of the addition of
// [BenchmarkMD5Vuln] to serve as a comparison.
func md5Baseline(v *claircore.Vulnerability) (string, []byte) {
	var b bytes.Buffer
	b.WriteString(v.Name)
	b.WriteString(v.Description)
	b.WriteString(v.Issued.String())
	b.WriteString(v.Links)
	b.WriteString(v.Severity)
	if v.Package != nil {
		b.WriteString(v.Package.Name)
		b.WriteString(v.Package.Version)
		b.WriteString(v.Package.Module)
		b.WriteString(v.Package.Arch)
		b.WriteString(wart.StringFromPackageKind(v.Package.Kind))
	}
	if v.Dist != nil {
		b.WriteString(v.Dist.DID)
		b.WriteString(v.Dist.Name)
		b.WriteString(v.Dist.Version)
		b.WriteString(v.Dist.VersionCodeName)
		b.WriteString(v.Dist.VersionID)
		b.WriteString(v.Dist.Arch)
		b.WriteString(v.Dist.CPE.BindFS())
		b.WriteString(v.Dist.PrettyName)
	}
	if v.Repo != nil {
		b.WriteString(v.Repo.Name)
		b.WriteString(v.Repo.Key)
		b.WriteString(v.Repo.URI)
	}
	b.WriteString(v.ArchOperation.String())
	b.WriteString(v.FixedInVersion)
	if k, l, u := rangefmt(v.Range); k != nil {
		b.WriteString(*k)
		b.WriteString(l)
		b.WriteString(u)
	}
	s := md5.Sum(b.Bytes())
	return "md5", s[:]
}

func TestHashEquivalent(t *testing.T) {
	cfg := &quick.Config{
		MaxCount: 1000,
		Values: func(vs []reflect.Value, _ *rand.Rand) {
			gen := test.GenUniqueVulnerabilities(1, "test")
			vs[0] = reflect.ValueOf(gen[0])
		},
	}
	if err := quick.CheckEqual(md5Baseline, md5Vuln, cfg); err != nil {
		t.Error(err)
	}
}

func BenchmarkMD5Vuln(b *testing.B) {
	vs := test.GenUniqueVulnerabilities(1, "test")
	run := func(f func(*claircore.Vulnerability) (string, []byte)) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				kind, hash := f(vs[0])
				if kind != `md5` || len(hash) != 16 {
					b.Fatal("???")
				}
			}
		}
	}
	b.Run("Baseline", run(md5Baseline))
	b.Run("Current", run(md5Vuln))
}
