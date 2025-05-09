package rpm

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/quay/claircore/internal/rpm/rpmdb"
	"github.com/quay/claircore/internal/rpmver"
)

// Info is the package information extracted from the RPM header.
type Info struct {
	Name       string
	Version    string
	Release    string
	SourceRPM  string
	Module     string
	Arch       string
	Digest     string
	Signature  []byte // This is a PGP signature packet.
	dirname    []string
	dirindex   []int32
	basename   []string
	DigestAlgo int
	Epoch      int
}

// Load populates the receiver with information extracted from the provided
// [rpmdb.Header].
func (i *Info) Load(ctx context.Context, h *rpmdb.Header) error {
	for idx := range h.Infos {
		e := &h.Infos[idx]
		if _, ok := wantTags[e.Tag]; !ok {
			continue
		}
		v, err := h.ReadData(ctx, e)
		if err != nil {
			return err
		}
		switch e.Tag {
		case rpmdb.TagName:
			i.Name = v.(string)
		case rpmdb.TagEpoch:
			i.Epoch = int(v.([]int32)[0])
		case rpmdb.TagVersion:
			i.Version = v.(string)
		case rpmdb.TagRelease:
			i.Release = v.(string)
		case rpmdb.TagSourceRPM:
			i.SourceRPM = v.(string)
		case rpmdb.TagModularityLabel:
			i.Module = v.(string)
		case rpmdb.TagArch:
			i.Arch = v.(string)
		case rpmdb.TagPayloadDigestAlgo:
			i.DigestAlgo = int(v.([]int32)[0])
		case rpmdb.TagPayloadDigest:
			i.Digest = v.([]string)[0]
		case rpmdb.TagSigPGP:
			i.Signature = v.([]byte)
		case rpmdb.TagDirnames: // v5-only
			i.dirname = v.([]string)
		case rpmdb.TagDirindexes: // v5-only
			i.dirindex = v.([]int32)
		case rpmdb.TagBasenames: // v5-only
			i.basename = v.([]string)
		case rpmdb.TagFilenames:
			// Filenames is the tag used in rpm4 -- this is a best-effort for
			// supporting it. This should be exclusive with the
			// Dirnames/Dirindexes/Basenames tags.
			//
			// This takes the whole filenames value and splits it into an
			// rpm5-style dir+base.
			names := v.([]string)
			slices.Sort(names)
			i.dirname = make([]string, 0)
			i.dirindex = make([]int32, 0, len(names))
			i.basename = make([]string, 0, len(names))
			cur := -1
			for _, name := range names {
				dir, base := path.Split(name)
				i.basename = append(i.basename, base)
				if len(i.dirname) == 0 || i.dirname[cur] != dir {
					cur = len(i.dirname)
					i.dirname = append(i.dirname, dir)
				}
				i.dirindex = append(i.dirindex, int32(cur))
			}
		default:
			panic(fmt.Sprintf("programmer error: unhandled tag: %v", e.Tag))
		}
	}

	if b, d := len(i.basename), len(i.dirindex); b != d {
		return fmt.Errorf(`internal/rpm: Info: mismatched "base" and "dir" counts: %d, %d`, b, d)
	}
	if len(i.dirindex) != 0 {
		if v, bound := slices.Max(i.dirindex), len(i.dirname); int(v) >= bound {
			return fmt.Errorf(`internal/rpm: Info: invalid "dirindex": index %d is out-of-bounds (length %d)`, v, bound)
		}
	}

	return nil
}

// Path reconstructs the j-th path.
//
// We only want '/'-separated paths, even if running on some other, weird OS. It
// seems that RPM assumes '/' throughout.
//
// The paths coming out of rpm are absolute, so this function makes them
// [fs.FS]-valid paths.
func (i *Info) path(j int) string {
	return path.Join(i.dirname[i.dirindex[j]][1:], i.basename[j])
}

// Filenames returns an iterator over all paths in the [Info].
//
// The returned paths are [fs.FS]-valid.
func (i *Info) Filenames() iter.Seq[string] {
	return func(yield func(string) bool) {
		for j := range i.basename {
			if !yield(i.path(j)) {
				return
			}
		}
	}
}

// InsertIntoSet inserts filtered "relevant" paths into the provided [PathSet].
func (i *Info) InsertIntoSet(s *PathSet) {
	pat := filePatterns()
	for p := range i.Filenames() {
		if pat.MatchString(p) {
			s.paths[p] = struct{}{}
		}
	}
}

// NEVRA constructs a Name-Epoch-Version-Release-Architecture [rpmver.Version].
func (i *Info) NEVRA() rpmver.Version {
	return rpmver.Version{
		Name:         &i.Name,
		Architecture: &i.Arch,
		Epoch:        strconv.Itoa(i.Epoch),
		Version:      i.Version,
		Release:      i.Release,
	}
}

// Hint constructs a string suitable to be used as the "RepositoryHint".
func (i *Info) Hint() string {
	v := url.Values{}
	if i.Digest != "" {
		switch i.DigestAlgo {
		case 8:
			v.Set("hash", "sha256:"+i.Digest)
		}
	}
	if len(i.Signature) != 0 {
		prd := packet.NewReader(bytes.NewReader(i.Signature))
		p, err := prd.Next()
		for ; err == nil; p, err = prd.Next() {
			switch p := p.(type) {
			case *packet.SignatureV3:
				if p.SigType != 0 {
					continue
				}
				v.Set("key", fmt.Sprintf("%016x", p.IssuerKeyId))
			case *packet.Signature:
				if p.SigType != 0 || p.IssuerKeyId == nil {
					continue
				}
				v.Set("key", fmt.Sprintf("%016x", *p.IssuerKeyId))
			}
		}
	}
	return v.Encode()
}

// ModuleStream reports the module and stream from the full module version.
//
// It returns the empty string if the [Info] does not describe a package from a
// module.
func (i *Info) ModuleStream() string {
	if strings.Count(i.Module, ":") <= 1 {
		return ""
	}
	first := true
	idx := strings.IndexFunc(i.Module, func(r rune) bool {
		if r != ':' {
			return false
		}
		if first {
			first = false
			return false
		}
		return true
	})
	return i.Module[:idx]
}

// TODO(hank) This regexp-based strategy is not very robust.
// Long-term, we should add pattern matching akin to [yara] or file(1) as a
// plugin mechanism that all indexers can use. That way, the Go indexer
// could register a pattern and use a shared filter over the
// [fs.WalkDirFunc] while this package (and dpkg, etc) can tell that another
// indexer will find those files relevant.
//
// [yara]: https://github.com/VirusTotal/yara
var (
	// FilePatterns is a regular expression for *any* file that may need to be
	// recorded alongside a package.
	//
	// The tested strings are absolute paths.
	filePatterns = sync.OnceValue(func() *regexp.Regexp {
		pat := []string{
			`^.*/[^/]+\.[ejw]ar$`,                         // Jar files
			`^.*/site-packages/[^/]+\.egg-info/PKG-INFO$`, // Python packages
			`^.*/package.json$`,                           // npm packages
			`^.*/[^/]+\.gemspec$`,                         // ruby gems
			`^/usr/s?bin/[^/]+$`,                          // any executable
			`^/usr/libexec/[^/]+/[^/]+$`,                  // sometimes the executables are here too
		}
		return regexp.MustCompile(strings.Join(pat, `|`))
	})
)

var wantTags = map[rpmdb.Tag]struct{}{
	rpmdb.TagArch:              {},
	rpmdb.TagBasenames:         {},
	rpmdb.TagDirindexes:        {},
	rpmdb.TagDirnames:          {},
	rpmdb.TagEpoch:             {},
	rpmdb.TagFilenames:         {},
	rpmdb.TagModularityLabel:   {},
	rpmdb.TagName:              {},
	rpmdb.TagPayloadDigest:     {},
	rpmdb.TagPayloadDigestAlgo: {},
	rpmdb.TagRelease:           {},
	rpmdb.TagSigPGP:            {},
	rpmdb.TagSourceRPM:         {},
	rpmdb.TagVersion:           {},
}
