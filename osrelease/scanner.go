// Package osrelease provides an "os-release" distribution scanner.
package osrelease

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/baggageutil"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/cpe"
)

const (
	scannerName    = "os-release"
	scannerVersion = "v0.0.2"
	scannerKind    = "distribution"
)

const fpath = `etc/os-release`

var _ indexer.DistributionScanner = (*Scanner)(nil)
var _ indexer.VersionedScanner = (*Scanner)(nil)

// Scanner implements a scanner.DistributionScanner that examines os-release
// files, as documented at
// https://www.freedesktop.org/software/systemd/man/os-release.html
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return scannerKind }

// Scan reports any found os-release Distribution information in the provided
// layer.
//
// It's an expected outcome to return (nil, nil) when the os-release file is not
// present in the layer.
func (s *Scanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = baggageutil.ContextWithValues(ctx,
		"component", "osrelease/Scanner.Scan",
		"version", s.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := l.Reader()
	if err != nil {
		return nil, fmt.Errorf("osrelease: unable to open layer: %w", err)
	}
	defer r.Close()

	// iterate through the tar and attempt to parse each os-release file encountered.
	// on a successful parse return the distribution.
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	for ; err == nil && ctx.Err() == nil; hdr, err = tr.Next() {
		switch hdr.Typeflag {
		case tar.TypeReg:
			base := filepath.Base(hdr.Name)
			if base != "os-release" {
				continue
			}
			d, err := parse(ctx, tr)
			if err == nil {
				return []*claircore.Distribution{d}, nil
			}
		}
	}
	switch err {
	case nil:
	case io.EOF: // OK
	default:
		return nil, fmt.Errorf("encountered a tar error: %v", err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	zlog.Debug(ctx).Msg("didn't find an os-release file")
	return nil, nil
}

// Parse returns the distribution information from the file contents provided on
// r.
func parse(ctx context.Context, r io.Reader) (*claircore.Distribution, error) {
	ctx = baggageutil.ContextWithValues(ctx,
		"component", "osrelease/parse")
	defer trace.StartRegion(ctx, "parse").End()
	d := claircore.Distribution{
		Name: "Linux",
		DID:  "linux",
	}
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	for s.Scan() && ctx.Err() == nil {
		b := s.Bytes()
		switch {
		case len(b) == 0:
			continue
		case b[0] == '#':
			continue
		}
		eq := bytes.IndexRune(b, '=')
		if eq == -1 {
			return nil, fmt.Errorf("osrelease: malformed line %q", s.Text())
		}
		key := strings.TrimSpace(string(b[:eq]))
		value := strings.TrimSpace(string(b[eq+1:]))

		// The value side is defined to follow shell-like quoting rules, which I
		// take to mean:
		//
		// * Within single quotes, no characters are special, and escaping is
		//   not possible. The only special case that needs to be handled is
		//   getting a single quote, which is done in shell by ending the
		//   string, escaping a single quote, then starting a new string.
		//
		// * Within double quotes, single quotes are not special, but double
		//   quotes and a handful of other characters are, and almost the entire
		//   lower-case ASCII alphabet can be escaped to produce various
		//   codepoints.
		//
		// With these in mind, the arms of the switch below implement the first
		// case and a limited version of the second.
		switch value[0] {
		case '\'':
			value = strings.TrimFunc(value, func(r rune) bool { return r == '\'' })
			value = strings.ReplaceAll(value, `'\''`, `'`)
		case '"':
			// This only implements the metacharacters that are called out in
			// the os-release documentation.
			value = strings.TrimFunc(value, func(r rune) bool { return r == '"' })
			value = strings.NewReplacer(
				"\\`", "`",
				`\\`, `\`,
				`\"`, `"`,
				`\$`, `$`,
			).Replace(value)
		default:
		}

		switch key {
		case "ID":
			zlog.Debug(ctx).Msg("found ID")
			d.DID = value
		case "VERSION_ID":
			zlog.Debug(ctx).Msg("found VERSION_ID")
			d.VersionID = value
		case "BUILD_ID":
		case "VARIANT_ID":
		case "CPE_NAME":
			zlog.Debug(ctx).Msg("found CPE_NAME")
			wfn, err := cpe.Unbind(value)
			if err != nil {
				zlog.Warn(ctx).
					Err(err).
					Str("value", value).
					Msg("failed to unbind the cpe")
				break
			}
			d.CPE = wfn
		case "NAME":
			zlog.Debug(ctx).Msg("found NAME")
			d.Name = value
		case "VERSION":
			zlog.Debug(ctx).Msg("found VERSION")
			d.Version = value
		case "ID_LIKE":
		case "VERSION_CODENAME":
			zlog.Debug(ctx).Msg("found VERISON_CODENAME")
			d.VersionCodeName = value
		case "PRETTY_NAME":
			zlog.Debug(ctx).Msg("found PRETTY_NAME")
			d.PrettyName = value
		case "REDHAT_BUGZILLA_PRODUCT":
			zlog.Debug(ctx).Msg("using RHEL hack")
			// This is a dirty hack because the Red Hat OVAL database and the
			// CPE contained in the os-release file don't agree.
			d.PrettyName = value
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	zlog.Debug(ctx).Str("name", d.Name).Msg("found dist")
	return &d, nil
}
