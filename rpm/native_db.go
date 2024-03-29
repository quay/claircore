package rpm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rpm/internal/rpm"
)

// NativeDB is the interface implemented for in-process RPM database handlers.
type nativeDB interface {
	AllHeaders(context.Context) ([]io.ReaderAt, error)
	Validate(context.Context) error
}

// PackagesFromDB extracts the packages from the RPM headers provided by
// the database.
func packagesFromDB(ctx context.Context, pkgdb string, db nativeDB) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "packagesFromDB").End()
	rds, err := db.AllHeaders(ctx)
	if err != nil {
		return nil, fmt.Errorf("rpm: error reading headers: %w", err)
	}
	// Bulk allocations:
	ps := make([]claircore.Package, 0, len(rds))
	pkgs := make([]*claircore.Package, 0, len(rds))
	srcs := make([]claircore.Package, 0, len(rds)) // Worst-case size.
	src := make(map[string]*claircore.Package)
	src["(none)"] = nil
	var b strings.Builder

	for _, rd := range rds {
		var h rpm.Header
		if err := h.Parse(ctx, rd); err != nil {
			return nil, err
		}
		var info Info
		if err := info.Load(ctx, &h); err != nil {
			return nil, err
		}
		if info.Name == "gpg-pubkey" {
			// This is *not* an rpm package. It is just a public key stored in the rpm database.
			// Ignore this "package".
			continue
		}

		idx := len(ps)
		ps = append(ps, claircore.Package{
			Kind:      claircore.BINARY,
			Name:      info.Name,
			Arch:      info.Arch,
			PackageDB: pkgdb,
		})
		p := &ps[idx]
		var modStream string
		if strings.Count(info.Module, ":") > 1 {
			first := true
			idx := strings.IndexFunc(info.Module, func(r rune) bool {
				if r != ':' {
					return false
				}
				if first {
					first = false
					return false
				}
				return true
			})
			modStream = info.Module[:idx]
		}
		p.Module = modStream
		p.Version = constructEVR(&b, &info)
		p.RepositoryHint = constructHint(&b, &info)

		if s, ok := src[info.SourceNEVR]; ok {
			p.Source = s
		} else {
			s := strings.TrimSuffix(info.SourceNEVR, ".src.rpm")
			pos := len(s)
			for i := 0; i < 2; i++ {
				pos = strings.LastIndexByte(s[:pos], '-')
				if pos == -1 {
					return nil, fmt.Errorf("malformed NEVR: %q", info.SourceNEVR)
				}
			}

			idx := len(srcs)
			srcs = append(srcs, claircore.Package{
				Kind:    claircore.SOURCE,
				Name:    s[:pos],
				Version: strings.TrimPrefix(s[pos+1:], "0:"),
			})
			pkg := &srcs[idx]
			src[info.SourceNEVR] = pkg
			p.Source = pkg
			pkg.Module = modStream
		}

		pkgs = append(pkgs, p)
	}
	zlog.Debug(ctx).
		Int("packages", len(pkgs)).
		Int("sources", len(srcs)).
		Msg("processed rpm db")
	return pkgs, nil
}

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
// [rpm.Header].
func (i *Info) Load(ctx context.Context, h *rpm.Header) error {
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
		case rpm.TagName:
			i.Name = v.(string)
		case rpm.TagEpoch:
			i.Epoch = int(v.([]int32)[0])
		case rpm.TagVersion:
			i.Version = v.(string)
		case rpm.TagRelease:
			i.Release = v.(string)
		case rpm.TagSourceRPM:
			i.SourceNEVR = v.(string)
		case rpm.TagModularityLabel:
			i.Module = v.(string)
		case rpm.TagArch:
			i.Arch = v.(string)
		case rpm.TagPayloadDigestAlgo:
			i.DigestAlgo = int(v.([]int32)[0])
		case rpm.TagPayloadDigest:
			i.Digest = v.([]string)[0]
		case rpm.TagSigPGP:
			i.Signature = v.([]byte)
		case rpm.TagDirnames:
			dirname = v.([]string)
		case rpm.TagDirindexes:
			dirindex = v.([]int32)
		case rpm.TagBasenames:
			basename = v.([]string)
		case rpm.TagFilenames:
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
		`^/usr/bin/[^/]+$`,                            // any executable
	}
	filePatterns = regexp.MustCompile(strings.Join(pat, `|`))
}

var wantTags = map[rpm.Tag]struct{}{
	rpm.TagArch:              {},
	rpm.TagBasenames:         {},
	rpm.TagDirindexes:        {},
	rpm.TagDirnames:          {},
	rpm.TagEpoch:             {},
	rpm.TagFilenames:         {},
	rpm.TagModularityLabel:   {},
	rpm.TagName:              {},
	rpm.TagPayloadDigest:     {},
	rpm.TagPayloadDigestAlgo: {},
	rpm.TagRelease:           {},
	rpm.TagSigPGP:            {},
	rpm.TagSourceRPM:         {},
	rpm.TagVersion:           {},
}

func constructEVR(b *strings.Builder, info *Info) string {
	b.Reset()
	if info.Epoch != 0 {
		fmt.Fprintf(b, "%d:", info.Epoch)
	}
	b.WriteString(info.Version)
	b.WriteByte('-')
	b.WriteString(info.Release)
	return b.String()
}

func constructHint(b *strings.Builder, info *Info) string {
	b.Reset()
	if info.Digest != "" {
		b.WriteString("hash:")
		switch info.DigestAlgo {
		case 8:
			b.WriteString("sha256:")
			b.WriteString(info.Digest)
		}
	}
	if len(info.Signature) != 0 {
		prd := packet.NewReader(bytes.NewReader(info.Signature))
		p, err := prd.Next()
		for ; err == nil; p, err = prd.Next() {
			switch p := p.(type) {
			case *packet.SignatureV3:
				if p.SigType != 0 {
					continue
				}
				if b.Len() != 0 {
					b.WriteByte('|')
				}
				fmt.Fprintf(b, "key:%016x", p.IssuerKeyId)
			case *packet.Signature:
				if p.SigType != 0 || p.IssuerKeyId == nil {
					continue
				}
				if b.Len() != 0 {
					b.WriteByte('|')
				}
				fmt.Fprintf(b, "key:%016x", *p.IssuerKeyId)
			}
		}
	}
	return b.String()
}
