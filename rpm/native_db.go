package rpm

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
		if strings.Contains(info.Module, ":") {
			p.Module = info.Module
		}
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
			if strings.Contains(info.Module, ":") {
				pkg.Module = info.Module
			}
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
	Signature  []byte // This is a PGP signature packet.
	DigestAlgo int
	Epoch      int
}

func (i *Info) Load(ctx context.Context, h *rpm.Header) error {
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
		}
	}
	return nil
}

var wantTags = map[rpm.Tag]struct{}{
	rpm.TagArch:              {},
	rpm.TagEpoch:             {},
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
			}
		}
	}
	return b.String()
}
