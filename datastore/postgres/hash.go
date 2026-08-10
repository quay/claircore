package postgres

import (
	"crypto/md5"
	"hash"
	"io"
	"sync"
	"unsafe"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
)

// WriteString is effectively [io.WriteString], except with an extra hack to
// avoid an allocation when the writer is not also an [io.StringWriter].
func writeString(w io.Writer, s string) (int, error) {
	if sw, ok := w.(io.StringWriter); ok {
		return sw.WriteString(s)
	}
	// SAFETY: Mutating the returned slice's data breaks Go's invariant that strings
	// are immutable. Don't do it!
	b := unsafe.Slice(unsafe.StringData(s), len(s))
	return w.Write(b)
}

const (
	hashMD5 = `md5`
)

var md5Pool sync.Pool

func getMD5() hash.Hash {
	if v := md5Pool.Get(); v != nil {
		return v.(hash.Hash)
	}
	return md5.New()
}

func putMD5(h hash.Hash) {
	h.Reset()
	md5Pool.Put(h)
}

// Md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *claircore.Vulnerability) (string, []byte) {
	h := getMD5()
	defer putMD5(h)
	writeString(h, v.Name)
	writeString(h, v.Description)
	writeString(h, v.Issued.String())
	writeString(h, v.Links)
	writeString(h, v.Severity)
	if v.Package != nil {
		writeString(h, v.Package.Name)
		writeString(h, v.Package.Version)
		writeString(h, v.Package.Module)
		writeString(h, v.Package.Arch)
		writeString(h, wart.StringFromPackageKind(v.Package.Kind))
	}
	if v.Dist != nil {
		writeString(h, v.Dist.DID)
		writeString(h, v.Dist.Name)
		writeString(h, v.Dist.Version)
		writeString(h, v.Dist.VersionCodeName)
		writeString(h, v.Dist.VersionID)
		writeString(h, v.Dist.Arch)
		writeString(h, v.Dist.CPE.BindFS())
		writeString(h, v.Dist.PrettyName)
	}
	if v.Repo != nil {
		writeString(h, v.Repo.Name)
		writeString(h, v.Repo.Key)
		writeString(h, v.Repo.URI)
	}
	writeString(h, v.ArchOperation.String())
	writeString(h, v.FixedInVersion)
	if k, l, u := rangefmt(v.Range); k != nil {
		writeString(h, *k)
		writeString(h, l)
		writeString(h, u)
	}
	return hashMD5, h.Sum(nil)
}
