// Package jar implements a scanner on Java archive (jar) files.
//
// In addition to bog standard archives, this package attempts to handle more
// esoteric uses, also.
//
// Throughout the code and comments, "jar" should be understood to mean "any
// kind of JVM archive." A brief primer on the different kinds:
//
// * jar:
//   Java Archive. It's a zip with a manifest file, some compiled class files,
//   and other assets.
//
// * fatjar/onejar:
//   Some jars unpacked, merged, then repacked. I gather this isn't in favor in
//   the java scene.
//
// * war:
//   Webapp Archive. These are consumed by application servers like Tomcat, and
//   are an all-in-one of code, dependencies, and metadata for configuring the
//   server.
//
// * ear:
//   Enterprise Archive. These are bundles of wars, with hook points for
//   configuration. They're only used on JEE servers, so they're comparatively
//   rare in the real world.
package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

// Header is the magic bytes at the beginning of a jar.
//
// JAR files are documented as only using the "standard" zip magic number.
// There are two other magic numbers (ending in "\x05\x06" and "\x07\x08"
// respectively) for zips, but they should not be used.
var Header = []byte{'P', 'K', 0x03, 0x04}

// MinSize is the absolute minimum size for a jar.
//
// This is the size of an empty zip. Files smaller than this cannot be jars.
const MinSize = 22

// Parse returns Info structs describing all of the discovered "artifacts" in
// the jar.
//
// POM properties are a preferred source of information, falling back to
// examining the jar manifest and then looking at the name. Anything that looks
// like a jar bundled into the archive is also examined.
//
// The provided name is expected to be the full path within the layer to the jar
// file being provided as "z".
func Parse(ctx context.Context, name string, z *zip.Reader) ([]Info, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "java/jar/Parse"),
		label.String("jar", name))

	// This uses an admittedly non-idiomatic, C-like goto construction. We want
	// to attempt a few heuristics and keep the results of the first one that
	// looks good. This does mean that there are restrictions on declarations in
	// the following block.

	var ret []Info
	var i Info
	var err error
	base := filepath.Base(name)
	// Try the pom.properties files first. Fatjars hopefully have the multiple
	// properties files preserved.
	ret, err = extractProperties(ctx, base, z)
	switch {
	case errors.Is(err, nil):
		zlog.Debug(ctx).
			Msg("using discovered properties file(s)")
		goto Finish
	case errors.Is(err, errUnpopulated):
	case strings.HasPrefix(base, "javax") && errors.Is(err, ErrNotAJar):
	default:
		return nil, err
	}
	// Look at the jar manifest if that fails.
	i, err = extractManifest(ctx, base, z)
	switch {
	case errors.Is(err, nil):
		zlog.Debug(ctx).
			Msg("using discovered manifest")
		ret = append(ret, i)
		goto Finish
	case errors.Is(err, errUnpopulated):
	case strings.HasPrefix(base, "javax") && errors.Is(err, ErrNotAJar):
	default:
		return nil, err
	}
	// As a last resort, just look at the name of the jar.
	i, err = checkName(ctx, name)
	switch {
	case errors.Is(err, nil):
		zlog.Debug(ctx).
			Msg("using name mangling")
		ret = append(ret, i)
		goto Finish
	case errors.Is(err, errUnpopulated):
	default:
		return nil, err
	}
	// If we haven't jumped past this point, this is almost certainly not a jar,
	// so return an error.
	return nil, mkErr("", unidentified(base))

Finish:
	// Now, we need to examine any jars bundled in this jar.
	inner, err := extractInner(ctx, name, z)
	if err != nil {
		return nil, err
	}
	if ct := len(inner); ct != 0 {
		zlog.Debug(ctx).
			Int("count", ct).
			Msg("found embedded jars")
	}
	ret = append(ret, inner...)

	return ret, nil
}

// ExtractManifest attempts to open the manifest file at the well-known path.
//
// Reports NotAJar if the file doesn't exist.
func extractManifest(ctx context.Context, name string, z fs.FS) (Info, error) {
	const manifestPath = `META-INF/MANIFEST.MF`
	mf, err := z.Open(manifestPath)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return Info{}, mkErr("manifest", notAJar(name, err))
	default:
		return Info{}, err
	}
	defer mf.Close()
	var i Info
	err = i.parseManifest(ctx, mf)
	if err != nil {
		return Info{}, err
	}
	i.Source = manifestPath
	return i, nil
}

// ExtractProperties pulls pom.properties files out of the META-INF directory
// of the provided fs.FS.
func extractProperties(ctx context.Context, name string, z fs.FS) ([]Info, error) {
	const filename = "pom.properties"
	var pf []string
	// Walk the fs looking for properties files.
	// We should end up with one info for every properties file.
	wf := func(path string, d fs.DirEntry, err error) error {
		// Tolerate no errors. We also need to walk everything.
		switch {
		case err != nil:
			return err
		case d.Name() != filename:
			return nil
		}
		zlog.Info(ctx).
			Str("path", path).
			Msg("found properties file")
		pf = append(pf, path)
		return nil
	}
	err := fs.WalkDir(z, `META-INF`, wf)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return nil, mkErr("properties", notAJar(name, err))
	default:
		return nil, err
	}
	ret := make([]Info, len(pf))
	for i, p := range pf {
		f, err := z.Open(p)
		if err != nil {
			return nil, err
		}
		err = ret[i].parseProperties(ctx, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		ret[i].Source = p
	}
	if len(ret) == 0 {
		zlog.Debug(ctx).Msg("properties not found")
		return nil, errUnpopulated
	}
	return ret, nil
}

// ExtractInner recurses into anything that looks like a jar in "z".
func extractInner(ctx context.Context, outer string, z fs.FS) ([]Info, error) {
	ctx = baggage.ContextWithValues(ctx, label.String("parent", outer))
	var ret []Info
	// Zips need random access, so allocate a buffer for any we find.
	// It's grown to the initial size upon first use.
	var buf bytes.Buffer
	var grow sync.Once
	const bufSz = 4 * 1024 * 1024
	h := sha1.New()
	wf := func(path string, d fs.DirEntry, err error) error {
		// Tolerate no errors. We also need to walk everything.
		// This has a series of checks before calling Parse:
		switch {
		case err != nil:
			return err
		case !checkExt(d.Name()): // Check name
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		// Check size
		if fi.Size() < MinSize {
			zlog.Debug(ctx).Str("member", d.Name()).Msg("not actually a jar: too small")
			return nil
		}
		f, err := z.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		grow.Do(func() { buf.Grow(bufSz) })
		buf.Reset()
		h.Reset()
		sz, err := buf.ReadFrom(io.TeeReader(f, h))
		if err != nil {
			return err
		}
		bs := buf.Bytes()
		// Check header.
		if !bytes.Equal(bs[:4], Header) {
			zlog.Debug(ctx).Str("member", d.Name()).Msg("not actually a jar: bad header")
			return nil
		}
		// Okay, now reasonably certain this is a jar.
		zr, err := zip.NewReader(bytes.NewReader(bs), sz)
		if err != nil {
			return err
		}
		ps, err := Parse(ctx, d.Name(), zr)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, ErrNotAJar) || errors.Is(err, ErrUnidentified):
			zlog.Debug(ctx).
				Str("member", d.Name()).
				Err(err).
				Msg("not actually a jar")
			return nil
		default:
			return err
		}
		c := make([]byte, sha1.Size)
		h.Sum(c[:0])
		for i := range ps {
			ps[i].SHA = c
			ps[i].Source = outer + ":" + ps[i].Source
		}
		ret = append(ret, ps...)
		return nil
	}
	if err := fs.WalkDir(z, ".", wf); err != nil {
		return nil, fmt.Errorf("walking %s: %w", outer, err)
	}
	if len(ret) == 0 {
		zlog.Debug(ctx).
			Msg("found no bundled jars")
	}
	return ret, nil
}

// NameRegexp is used to attempt to pull a name and version out of a jar's
// filename.
var nameRegexp = regexp.MustCompile(`([[:graph:]]+)-([[:digit:]][\-.[:alnum:]]*(?:-SNAPSHOT)?)\.jar`)

// CheckName tries to populate the Info just from the above regexp.
func checkName(ctx context.Context, name string) (Info, error) {
	m := nameRegexp.FindStringSubmatch(filepath.Base(name))
	if m == nil {
		zlog.Debug(ctx).
			Msg("name not useful")
		return Info{}, errUnpopulated
	}
	return Info{
		Name:    m[1],
		Version: m[2],
		Source:  ".",
	}, nil
}

// CheckExt reports whether the string is an archive-like.
func checkExt(name string) bool {
	switch filepath.Ext(name) {
	case ".jar", ".ear", ".war":
		return true
	}
	return false
}

// Info reports the discovered information for a jar file.
//
// Any given jar may actually contain multiple jars or recombined classes.
type Info struct {
	// Name is the machine name found.
	//
	// Metadata that contains a "presentation" name isn't used to populate this
	// field.
	Name string
	// Version is the version.
	Version string
	// Source is the archive member used to populate the information. If the
	// name of the archive was used, this will be ".".
	Source string
	// SHA is populated with the SHA1 of the file if this entry was discovered
	// inside another archive.
	SHA []byte
}

func (i *Info) String() string {
	var b strings.Builder
	b.WriteString(i.Name)
	b.WriteByte('/')
	b.WriteString(i.Version)
	if len(i.SHA) != 0 {
		b.WriteString("(sha1:")
		hex.NewEncoder(&b).Write(i.SHA)
		b.WriteByte(')')
	}
	b.WriteString(" [")
	b.WriteString(i.Source)
	b.WriteByte(']')
	return b.String()
}

// ErrUnpopulated is returned by the parse* methods when they didn't populate
// the Info struct.
var errUnpopulated = errors.New("unpopulated")

// ParseManifest does what it says on the tin.
//
// This extracts "Main Attributes", as defined at
// https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html.
//
// Also note that this spec gives and example that's invalid per their little
// BNF grammar:
// https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Per-Entry_Attributes.
//
// I'm not sure what to do with that... perhaps bail and resort to an in-order,
// line-wise parser?
//
// This also examines "Bundle" metadata, aka OSGI metadata, as described in the
// spec: https://github.com/osgi/osgi/wiki/Release:-Bundle-Hook-Service-Specification-1.1
func (i *Info) parseManifest(ctx context.Context, r io.Reader) error {
	msg, err := mail.ReadMessage(io.MultiReader(r, bytes.NewReader([]byte("\n\n"))))
	if err != nil {
		return fmt.Errorf("unable to read manifest: %w", err)
	}
	// Sanity checks:
	switch {
	case !manifestVer.MatchString(msg.Header.Get("Manifest-Version")):
		v := msg.Header.Get("Manifest-Version")
		return fmt.Errorf("invalid manifest version: %q", v)
	case msg.Header.Get("Name") != "":
		// This shouldn't be happening in the Main section.
		return fmt.Errorf("martian manifest")
	}

	var name, version string
	switch {
	case msg.Header.Get("Bundle-SymbolicName") != "":
		n := msg.Header.Get("Bundle-SymbolicName")
		if i := strings.IndexByte(n, ';'); i != -1 {
			n = n[:i]
		}
		name = n
	case msg.Header.Get("Implementation-Vendor-Id") != "":
		// This attribute is marked as "Deprecated," but there's nothing that
		// provides the same information.
		name = msg.Header.Get("Implementation-Vendor-Id")
	}
	for _, key := range []string{
		"Bundle-Version",
		"Implementation-Version",
		"Specification-Version",
	} {
		if v := msg.Header.Get(key); v != "" {
			version = v
			break
		}
	}

	if name == "" || version == "" {
		zlog.Debug(ctx).
			Strs("attrs", []string{name, version}).
			Msg("manifest not useful")
		return errUnpopulated
	}
	i.Name = name
	i.Version = version
	return nil
}

// ManifestVer is a regexp describing a manifest version string.
//
// Our code doesn't need or prefer a certain manifest version, but every example
// seems to be "1.0"?
//
//	% find testdata/manifest -type f -exec awk '/Manifest-Version/{print}' '{}' +|sort|uniq
//	Manifest-Version: 1.0
var manifestVer = regexp.MustCompile(`[[:digit:]]+(\.[[:digit:]]+)*`)

// ParseProperties parses the pom properties file.
//
// This is the best-case scenario.
func (i *Info) parseProperties(ctx context.Context, r io.Reader) error {
	var group, artifact, version string
	s := bufio.NewScanner(r)
	for s.Scan() && (group == "" || artifact == "" || version == "") {
		b := bytes.TrimSpace(s.Bytes())
		ls := bytes.SplitN(b, []byte("="), 2)
		if len(ls) != 2 {
			continue
		}
		switch {
		case bytes.Equal(ls[0], []byte("groupId")):
			group = string(ls[1])
		case bytes.Equal(ls[0], []byte("artifactId")):
			artifact = string(ls[1])
		case bytes.Equal(ls[0], []byte("version")):
			version = string(ls[1])
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	if group == "" || artifact == "" || version == "" {
		zlog.Debug(ctx).
			Strs("attrs", []string{group, artifact, version}).
			Msg("properties not useful")
		return errUnpopulated
	}

	i.Name = group + ":" + artifact
	i.Version = version
	return nil
}
