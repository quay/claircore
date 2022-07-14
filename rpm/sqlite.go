package rpm

import (
	"bytes"
	"context"
	"fmt"
	"runtime/trace"
	"strconv"
	"strings"

	"github.com/quay/zlog"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rpm/sqlite"
)

func packagesFromInfos(ctx context.Context, db string, infos []sqlite.Info) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "packagesFromInfos").End()
	// Bulk allocations:
	ps := make([]claircore.Package, 0, len(infos))
	pkgs := make([]*claircore.Package, 0, len(infos))
	srcs := make([]claircore.Package, 0, len(infos)) // Worst-case size.
	src := make(map[string]*claircore.Package)
	src["(none)"] = nil
	var b strings.Builder

	for i := range infos {
		info := &infos[i]
		idx := len(ps)
		ps = append(ps, claircore.Package{
			Kind:      claircore.BINARY,
			Name:      info.Name,
			Arch:      info.Arch,
			PackageDB: db,
		})
		p := &ps[idx]
		if strings.Contains(info.Module, ":") {
			p.Module = info.Module
		}
		p.Version = constructEVR(&b, info)
		p.RepositoryHint = constructHint(&b, info)

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
			if info.Epoch != 0 {
				pkg.Version = strconv.Itoa(info.Epoch) + ":" + pkg.Version
			}
			if strings.Contains(info.Module, ":") {
				pkg.Module = info.Module
			}
		}

		pkgs = append(pkgs, p)
	}
	zlog.Debug(ctx).
		Int("packages", len(pkgs)).
		Int("sources", len(srcs)).
		Msg("processed sqlite db")
	return pkgs, nil
}

func constructEVR(b *strings.Builder, info *sqlite.Info) string {
	b.Reset()
	if info.Epoch != 0 {
		fmt.Fprintf(b, "%d:", info.Epoch)
	}
	b.WriteString(info.Version)
	b.WriteByte('-')
	b.WriteString(info.Release)
	return b.String()
}

func constructHint(b *strings.Builder, info *sqlite.Info) string {
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
				fmt.Fprintf(b, "key:%x", p.IssuerKeyId)
			}
		}
	}
	return b.String()
}
