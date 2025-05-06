package rpm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/rpmdb"
	"github.com/quay/claircore/internal/rpm/sqlite"
)

// NativeDB is the interface implemented for in-process RPM database handlers.
type nativeDB interface {
	AllHeaders(context.Context) ([]io.ReaderAt, error)
	Validate(context.Context) error
}

// ObjectResponse is a generic object that we're expecting to extract from
// RPM database, currently either a slice of Packages or Files.
type ObjectResponse interface {
	[]*claircore.Package | []claircore.File
}

// GetDBObjects does all the dirty work of extracting generic claircore objects
// from an RPM database. Provide it with a foundDB, the sys and a fn extract function
// it will create an implementation agnostic nativeDB and extract specific claircore
// objects from it.
func getDBObjects[T ObjectResponse](ctx context.Context, sys fs.FS, db foundDB, fn func(context.Context, string, nativeDB) (T, error)) (T, error) {
	var nat nativeDB
	switch db.Kind {
	case kindSQLite:
		r, err := sys.Open(path.Join(db.Path, `rpmdb.sqlite`))
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			zlog.Warn(ctx).Err(err).Msg("rpm: unable to open sqlite db")
			return nil, nil
		default:
			return nil, fmt.Errorf("rpm: unable to open sqlite db: %w", err)
		}
		defer func() {
			if err := r.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db")
			}
		}()
		f, err := os.CreateTemp(os.TempDir(), `rpmdb.sqlite.*`)
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
		}
		defer func() {
			if err := os.Remove(f.Name()); err != nil {
				zlog.Error(ctx).Err(err).Msg("unable to unlink sqlite db")
			}
			if err := f.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db")
			}
		}()
		zlog.Debug(ctx).Str("file", f.Name()).Msg("copying sqlite db out of FS")
		if _, err := io.Copy(f, r); err != nil {
			return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
		}
		if err := f.Sync(); err != nil {
			return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
		}
		sdb, err := sqlite.Open(f.Name())
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
		}
		defer sdb.Close()
		nat = sdb
	case kindBDB:
		f, err := sys.Open(path.Join(db.Path, `Packages`))
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading bdb db: %w", err)
		}
		defer f.Close()
		r, done, err := mkAt(ctx, db.Kind, f)
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading bdb db: %w", err)
		}
		defer done()
		var bpdb bdb.PackageDB
		if err := bpdb.Parse(r); err != nil {
			return nil, fmt.Errorf("rpm: error parsing bdb db: %w", err)
		}
		nat = &bpdb
	case kindNDB:
		f, err := sys.Open(path.Join(db.Path, `Packages.db`))
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading ndb db: %w", err)
		}
		defer f.Close()
		r, done, err := mkAt(ctx, db.Kind, f)
		if err != nil {
			return nil, fmt.Errorf("rpm: error reading ndb db: %w", err)
		}
		defer done()
		var npdb ndb.PackageDB
		if err := npdb.Parse(r); err != nil {
			return nil, fmt.Errorf("rpm: error parsing ndb db: %w", err)
		}
		nat = &npdb
	default:
		panic("programmer error: bad kind: " + db.Kind.String())
	}
	if err := nat.Validate(ctx); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("rpm: invalid native DB")
		return nil, nil
	}
	ps, err := fn(ctx, db.String(), nat)
	if err != nil {
		return nil, fmt.Errorf("rpm: error reading native db: %w", err)
	}

	return ps, nil
}

// FilesFromDB extracts the files that were instsalled via RPM from the
// RPM headers.
func filesFromDB(ctx context.Context, _ string, db nativeDB) ([]claircore.File, error) {
	defer trace.StartRegion(ctx, "filesFromDB").End()
	rds, err := db.AllHeaders(ctx)
	if err != nil {
		return nil, fmt.Errorf("rpm: error reading headers: %w", err)
	}
	var files []claircore.File
	for _, rd := range rds {
		var h rpmdb.Header
		if err := h.Parse(ctx, rd); err != nil {
			return nil, err
		}
		var info Info
		if err := info.Load(ctx, &h); err != nil {
			return nil, err
		}
		for _, f := range info.Filenames {
			files = append(files, claircore.File{
				Path: f,
			})
		}
	}
	return files, nil
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
		var h rpmdb.Header
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

func constructHint(_ *strings.Builder, info *Info) string {
	v := url.Values{}
	if info.Digest != "" {
		switch info.DigestAlgo {
		case 8:
			v.Set("hash", "sha256:"+info.Digest)
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

func mkAt(ctx context.Context, k dbKind, f fs.File) (io.ReaderAt, func(), error) {
	if r, ok := f.(io.ReaderAt); ok {
		return r, func() {}, nil
	}
	spool, err := os.CreateTemp(os.TempDir(), `Packages.`+k.String()+`.`)
	if err != nil {
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}
	ctx = zlog.ContextWithValues(ctx, "file", spool.Name())
	if err := os.Remove(spool.Name()); err != nil {
		zlog.Error(ctx).Err(err).Msg("unable to remove spool; file leaked!")
	}
	zlog.Debug(ctx).
		Msg("copying db out of fs.FS")
	if _, err := io.Copy(spool, f); err != nil {
		if err := spool.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close spool")
		}
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}
	return spool, closeSpool(ctx, spool), nil
}

func closeSpool(ctx context.Context, f *os.File) func() {
	return func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close spool")
		}
	}
}
