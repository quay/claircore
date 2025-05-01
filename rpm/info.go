package rpm

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/zlog"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/quay/claircore/internal/rpm/rpmdb"
	"github.com/quay/claircore/internal/rpmver"
)

// Info is the package information extracted from the RPM header.
type Info struct {
	Name       string
	Version    string
	Release    string
	SourceNEVR string
	Module     string
	Arch       string
	Digest     string
	Signature  []byte   // This is a PGP signature packet.
	Filenames  []string // Filtered by the [filePatterns] regexp.
	DigestAlgo int
	Epoch      int
}

// Load populates the receiver with information extracted from the provided
// [rpmdb.Header].
func (i *Info) Load(ctx context.Context, h *rpmdb.Header) error {
	var dirname, basename []string
	var dirindex []int32
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
			i.SourceNEVR = v.(string)
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
		case rpmdb.TagDirnames:
			dirname = v.([]string)
		case rpmdb.TagDirindexes:
			dirindex = v.([]int32)
		case rpmdb.TagBasenames:
			basename = v.([]string)
		case rpmdb.TagFilenames:
			// Filenames is the tag used in rpm4 -- this is a best-effort for
			// supporting it.
			for _, name := range v.([]string) {
				if !filePatterns.MatchString(name) {
					// Record the name as a relative path, as that's what we use
					// everywhere else.
					i.Filenames = append(i.Filenames, name[1:])
				}
			}
		}
	}

	// Catch panics from malformed headers. Can't think of a better way to
	// handle this.
	defer func() {
		if r := recover(); r == nil {
			return
		}
		zlog.Warn(ctx).
			Str("name", i.Name).
			Strs("basename", basename).
			Strs("dirname", dirname).
			Ints32("dirindex", dirindex).
			Msg("caught panic in filename construction")
		i.Filenames = nil
	}()
	for j := range basename {
		// We only want '/'-separated paths, even if running on some other,
		// weird OS. It seems that RPM assumes '/' throughout.
		name := path.Join(dirname[dirindex[j]], basename[j])
		if filePatterns.MatchString(name) {
			// Record the name as a relative path, as that's what we use
			// everywhere else.
			i.Filenames = append(i.Filenames, name[1:])
		}
	}
	return nil
}

// NEVRA constructs a Name-Epoch-Version-Release-Architecture [rpmver.Version].
func (i *Info) NEVRA() rpmver.Version {
	return rpmver.Version{
		Name:         &([]string{i.Name})[0],
		Architecture: &([]string{i.Arch})[0],
		Epoch:        strconv.Itoa(i.Epoch),
		Version:      i.Version,
		Release:      i.Release,
	}
}

// Hint constructs a string suitable to be use as the "RepositoryHint".
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

// FilePatterns is a regular expression for *any* file that may need to be
// recorded alongside a package.
//
// The tested strings are absolute paths.
var filePatterns *regexp.Regexp

func init() {
	// TODO(hank) The blanket binary pattern is too broad and can miss things.
	// Long-term, we should add pattern matching akin to [yara] or file(1) as a
	// plugin mechanism that all indexers can use. That way, the Go indexer
	// could register a pattern and use a shared filter over the
	// [fs.WalkDirFunc] while this package (and dpkg, etc) can tell that another
	// indexer will find those files relevant.
	//
	// [yara]: https://github.com/VirusTotal/yara
	pat := []string{
		`^.*/[^/]+\.jar$`, // Jar files
		`^.*/site-packages/[^/]+\.egg-info/PKG-INFO$`, // Python packages
		`^.*/package.json$`,                           // npm packages
		`^.*/[^/]+\.gemspec$`,                         // ruby gems
		`^/usr/s?bin/[^/]+$`,                          // any executable
		"^/usr/libexec/[^/]+/[^/]+$",                  // sometimes the executables are here too
	}
	filePatterns = regexp.MustCompile(strings.Join(pat, `|`))
}

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
