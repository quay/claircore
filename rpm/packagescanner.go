package rpm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const (
	pkgName    = "rpm"
	pkgKind    = "package"
	pkgVersion = "4"
)

// DbNames is a set of files that make up an rpm database.
var dbnames = map[string]struct{}{
	"Packages": {},
}

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// This looks for directories that look like rpm databases and examines the
// files it finds there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return pkgName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

// Scan attempts to find rpm databases within the layer and enumerate the
// packages there.
//
// A return of (nil, nil) is expected if there's no rpm database.
//
// The external command "rpm" is used and expected to be in PATH.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "rpm/Scanner.Scan"),
		label.String("version", ps.Version()),
		label.String("layer", layer.Hash.String()))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("rpm: cannot seek on returned layer Reader")
	}

	// Map of directory to confidence score. Confidence of len(dbnames) means
	// it's almost certainly an rpm database.
	possible := make(map[string]int)
	tr := tar.NewReader(rd)
	// Find possible rpm dbs
	// If none found, return
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n := filepath.Base(h.Name)
		d := filepath.Dir(h.Name)
		if _, ok := dbnames[n]; ok && checkMagic(ctx, tr) {
			possible[d]++
		}
	}
	if err != io.EOF {
		return nil, err
	}
	if len(possible) == 0 {
		return nil, nil
	}
	found := make([]string, 0)
	for k, score := range possible {
		if score == len(dbnames) {
			found = append(found, filepath.Join("/", k))
		}
	}
	zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")
	if len(found) == 0 {
		return nil, nil
	}

	root, err := ioutil.TempDir("", "rpmscanner.")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			// Raising an error should notify an operator?
			//
			// It's this or panic.
			zlog.Error(ctx).Err(err).Msg("error removing extracted files")
		}
	}()
	empty := filepath.Join(os.TempDir(), "rpm.emptyfile")
	ef, err := os.Create(empty)
	if err != nil {
		return nil, err
	}
	if err := ef.Close(); err != nil {
		return nil, err
	}

	// Extract tarball
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := rd.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rpm: unable to seek: %w", err)
	}
	tr = tar.NewReader(rd)
	const (
		// Any mode bits need to be or'd with these constants so that this
		// process can always remove and traverse files it writes.
		dirMode  = 0o0700
		fileMode = 0o0600
	)
	// For logging what we've done.
	var stats struct {
		Reg, Link, Symlink, Dir, Whiteout int
		OutOfOrder                        int
	}
	// Made tracks directory creation to prevent excessive mkdir calls.
	made := map[string]struct{}{root: {}}
	// DeferLn is for queuing up out-of-order hard links.
	var deferLn [][2]string
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		if strings.HasPrefix(filepath.Base(h.Name), ".wh.") {
			// Whiteout, skip.
			stats.Whiteout++
			continue
		}
		// Build the path on the filesystem.
		tgt := relPath(root, h.Name)
		// Since tar, as a format, doesn't impose ordering requirements, make
		// sure to create all parent directories of the current entry.
		d := filepath.Dir(tgt)
		if _, ok := made[d]; !ok {
			if err := os.MkdirAll(d, dirMode); err != nil {
				return nil, err
			}
			made[d] = struct{}{}
			stats.OutOfOrder++
		}

		// Populate the target file.
		var err error
		switch h.Typeflag {
		case tar.TypeDir:
			m := h.FileInfo().Mode() | dirMode
			if _, ok := made[tgt]; ok {
				// If we had made this directory by seeing a child first, touch
				// up the permissions.
				err = os.Chmod(tgt, m)
				break
			}
			err = os.Mkdir(tgt, m)
			// Make sure to preempt the MkdirAll call if the entries were
			// ordered nicely.
			made[d] = struct{}{}
			stats.Dir++
		case tar.TypeReg:
			m := h.FileInfo().Mode() | fileMode
			var f *os.File
			f, err = os.OpenFile(tgt, os.O_CREATE|os.O_WRONLY, m)
			if err != nil {
				break // Handle after the switch.
			}
			_, err = io.Copy(f, tr)
			if err := f.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("error closing new file")
			}
			stats.Reg++
		case tar.TypeSymlink:
			// Normalize the link target into the root.
			ln := relPath(root, h.Linkname)
			err = os.Symlink(ln, tgt)
			stats.Symlink++
		case tar.TypeLink:
			// Normalize the link target into the root.
			ln := relPath(root, h.Linkname)
			_, exists := os.Lstat(ln)
			switch {
			case errors.Is(exists, nil):
				err = os.Link(ln, tgt)
			case errors.Is(exists, os.ErrNotExist):
				// Push onto a queue to fix later. Link(2) is documented to need
				// a valid target, unlike symlink(2), which allows a missing
				// target. Combined with tar's lack of ordering, this seems like
				// the best solution.
				deferLn = append(deferLn, [2]string{ln, tgt})
			default:
				err = exists
			}
			stats.Link++
		default:
			// Skip everything else: Can't mknod as an unprivileged user and
			// fifos are only useful to a running system.
		}
		if err != nil {
			return nil, err
		}
	}
	if err != io.EOF {
		return nil, err
	}
	for _, l := range deferLn {
		if err := os.Link(l[0], l[1]); err != nil {
			zlog.Debug(ctx).
				Err(err).
				Msg("cross-layer (or invalid) hardlink found")
			if err := os.Link(empty, l[1]); err != nil {
				return nil, err
			}
		}
	}
	if ct := len(deferLn); ct != 0 {
		zlog.Debug(ctx).
			Int("count", ct).
			Msg("processed deferred links")
	}

	zlog.Info(ctx).
		Int("file", stats.Reg).
		Int("dir", stats.Dir).
		Int("dir(out of order)", stats.OutOfOrder).
		Int("symlink", stats.Symlink).
		Int("link", stats.Link).
		Int("whiteout", stats.Whiteout).
		Msg("extracted layer")

	var pkgs []*claircore.Package
	// Using --root and --dbpath, run rpm query on every suspected database
	for _, db := range found {
		zlog.Debug(ctx).Str("db", db).Msg("examining database")

		cmd := exec.CommandContext(ctx, "rpm",
			`--root`, root, `--dbpath`, db,
			`--query`, `--all`, `--queryformat`, queryFmt)
		r, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		errbuf := bytes.Buffer{}
		cmd.Stderr = &errbuf
		zlog.Debug(ctx).Str("db", db).Strs("cmd", cmd.Args).Msg("rpm invocation")
		if err := cmd.Start(); err != nil {
			r.Close()
			return nil, err
		}
		// Use a closure to defer the Close call.
		if err := func() error {
			defer r.Close()
			srcs := make(map[string]*claircore.Package)
			s := bufio.NewScanner(r)
			s.Split(querySplit)

			for s.Scan() {
				p, err := parsePackage(ctx, srcs, bytes.NewBuffer(s.Bytes()))
				if err != nil {
					return err
				}
				p.PackageDB = db
				pkgs = append(pkgs, p)
			}

			return s.Err()
		}(); err != nil {
			if errbuf.Len() != 0 {
				zlog.Warn(ctx).
					Str("db", db).
					Strs("cmd", cmd.Args).
					Str("err", errbuf.String()).
					Msg("error output")
			}
			return nil, fmt.Errorf("rpm: error reading rpm output: %w", err)
		}
		if err := cmd.Wait(); err != nil {
			return nil, err
		}
	}

	return pkgs, nil
}

// This is the query format we're using to get data out of rpm.
//
// There's XML output, but it's all jacked up.
const queryFmt = `%{name}\n` +
	`%{evr}\n` +
	`%{payloaddigestalgo}:%{payloaddigest}\n` +
	`%{sigpgp:pgpsig}\n` +
	`%{sourcerpm}\n` +
	`%{RPMTAG_MODULARITYLABEL}\n` +
	`%{ARCH}\n` +
	`.\n`
const delim = "\n.\n"

func querySplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.Index(data, []byte(delim))
	switch {
	case len(data) == 0 && atEOF:
		return 0, nil, io.EOF
	case i == -1 && atEOF:
		return 0, nil, errors.New("invalid format")
	case i == -1 && !atEOF:
		return 0, nil, nil
	default:
	}
	tok := data[:i]
	return len(tok) + len(delim), tok, nil
}

func parsePackage(ctx context.Context, src map[string]*claircore.Package, buf *bytes.Buffer) (*claircore.Package, error) {
	defer trace.StartRegion(ctx, "parsePackage").End()
	p := claircore.Package{
		Kind: claircore.BINARY,
	}
	var err error
	var line string

	for i := 0; ; i++ {
		// Look at the "queryFmt" string for the line numbers.
		line, err = buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(none)") {
			continue
		}
		if line == "" && err == nil {
			zlog.Info(ctx).
				Str("package", p.Name).
				Int("lineno", i).
				Msg("unexpected empty line")
			continue
		}
		switch i {
		case 0:
			p.Name = line
		case 1:
			p.Version = line
		case 2:
			p.RepositoryHint = "hash:"
			switch line[0] {
			case '8': // sha256
				p.RepositoryHint += "sha256" + line[1:]
			}
		case 3:
			const delim = `Key ID `
			i := strings.Index(line, delim)
			if i == -1 { // ???
				break
			}
			p.RepositoryHint += "|key:" + line[i+len(delim):]
		case 4:
			line = strings.TrimSuffix(line, ".src.rpm")
			sp := strings.Split(line, "-")
			name := strings.Join(sp[:len(sp)-2], "-")
			if s, ok := src[name]; ok {
				p.Source = s
				break
			}
			p.Source = &claircore.Package{
				Name:    name,
				Version: sp[len(sp)-2] + "-" + sp[len(sp)-1],
				Kind:    claircore.SOURCE,
			}
			src[name] = p.Source
		case 5:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
			if p.Source != nil {
				p.Source.Module = moduleStream
			}
		case 6:
			p.Arch = line
		}
		switch err {
		case nil:
		case io.EOF:
			return &p, nil
		default:
			return nil, err
		}
	}
}

// CheckMagic looks at bit of the provided Reader to see if it looks like a
// BerkeleyDB file.
//
// According to the libmagic database I looked at:
//
//	# Hash 1.85/1.86 databases store metadata in network byte order.
//	# Btree 1.85/1.86 databases store the metadata in host byte order.
//	# Hash and Btree 2.X and later databases store the metadata in host byte order.
//
// Since this process can't (and doesn't want to) know the endian-ness of the
// layer's eventual host, we just look both ways for everything.
func checkMagic(ctx context.Context, r io.Reader) bool {
	const (
		Hash  = 0x00061561
		BTree = 0x00053162
		Queue = 0x00042253
		Log   = 0x00040988
	)
	// Most hosts are still x86, try LE first.
	be := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}
	b := make([]byte, 4)

	// Look at position 0 and 12 for a magic number.
	for _, discard := range []int64{0, 8} {
		if _, err := io.Copy(io.Discard, io.LimitReader(r, discard)); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unexpected error checking magic")
			return false
		}
		if _, err := io.ReadFull(r, b); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unexpected error checking magic")
			return false
		}
		for _, o := range be {
			n := o.Uint32(b)
			if n == Hash || n == BTree || n == Queue || n == Log {
				return true
			}
		}
	}

	return false
}

// RelPath takes a member and forcibly interprets it as a path underneath root.
//
// This should be used anytime a path for a new file on disk is needed when
// unpacking a tar.
func relPath(root, member string) string {
	return filepath.Join(root, filepath.Join("/", member))
}
