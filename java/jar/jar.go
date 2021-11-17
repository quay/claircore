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
	"path"
	"path/filepath"
	"regexp"
	"strings"

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
func extractManifest(ctx context.Context, name string, z *zip.Reader) (Info, error) {
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
// of the provided zip.
func extractProperties(ctx context.Context, name string, z *zip.Reader) ([]Info, error) {
	const filename = "pom.properties"
	if _, err := z.Open(`META-INF`); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, mkErr("properties", notAJar(name, err))
		}
		return nil, mkErr("properties", err)
	}
	var pf []string
	// Go through the zip looking for properties files.
	// We should end up with one info for every properties file.
	for _, f := range z.File {
		// Normalize the path to handle any attempted traversals
		// encoded in the file names.
		p := normName(f.Name)
		if path.Base(p) == filename {
			zlog.Info(ctx).
				Str("path", p).
				Msg("found properties file")
			pf = append(pf, p)
		}
	}
	if len(pf) == 0 {
		zlog.Debug(ctx).Msg("properties not found")
		return nil, errUnpopulated
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
	return ret, nil
}

// ExtractInner recurses into anything that looks like a jar in "z".
func extractInner(ctx context.Context, outer string, z *zip.Reader) ([]Info, error) {
	ctx = baggage.ContextWithValues(ctx, label.String("parent", outer))
	var ret []Info
	// Zips need random access, so allocate a buffer for any we find.
	var buf bytes.Buffer
	h := sha1.New()
	checkFile := func(ctx context.Context, f *zip.File) error {
		name := normName(f.Name)
		// Check name.
		if !checkExt(name) {
			return nil
		}
		fi := f.FileInfo()
		// Check size.
		if fi.Size() < MinSize {
			zlog.Debug(ctx).Str("member", name).Msg("not actually a jar: too small")
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		buf.Reset()
		h.Reset()
		sz, err := buf.ReadFrom(io.TeeReader(rc, h))
		if err != nil {
			return err
		}
		bs := buf.Bytes()
		// Check header.
		if !bytes.Equal(bs[:4], Header) {
			zlog.Debug(ctx).Str("member", name).Msg("not actually a jar: bad header")
			return nil
		}
		// Okay, now reasonably certain this is a jar.
		zr, err := zip.NewReader(bytes.NewReader(bs), sz)
		if err != nil {
			return err
		}
		ps, err := Parse(ctx, name, zr)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, ErrNotAJar) || errors.Is(err, ErrUnidentified):
			zlog.Debug(ctx).
				Str("member", name).
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

	for _, f := range z.File {
		if err := checkFile(ctx, f); err != nil {
			return nil, fmt.Errorf("walking %s: %w", outer, err)
		}
	}
	if len(ret) == 0 {
		zlog.Debug(ctx).
			Msg("found no bundled jars")
	}
	return ret, nil
}

// NormName normalizes a name from a raw zip file header.
//
// This should be used in all cases that pull the name out of the zip header.
func normName(p string) string {
	return path.Join("/", p)[1:]
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
// This also examines "Bundle" metadata, aka OSGI metadata, as described in the
// spec: https://github.com/osgi/osgi/wiki/Release:-Bundle-Hook-Service-Specification-1.1
func (i *Info) parseManifest(ctx context.Context, r io.Reader) error {
	rd := newMainSectionReader(r)
	msg, err := mail.ReadMessage(rd)
	if err != nil {
		return fmt.Errorf("unable to read manifest: %w", err)
	}
	// Sanity checks:
	switch {
	case len(msg.Header) == 0:
		return errors.New("no headers found")
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

// NewMainSectionReader returns a reader wrapping "r" that reads until the main
// section of the manifest ends, or EOF. It appends newlines as needed to make
// the manifest an rfc822 compatible.
//
// To quote from the spec:
//
//	A JAR file manifest consists of a main section followed by a list of
//	sections for individual JAR file entries, each separated by a newline. Both
//	the main section and individual sections follow the section syntax specified
//	above. They each have their own specific restrictions and rules.
//
//	The main section contains security and configuration information about the
//	JAR file itself, as well as the application or extension that this JAR file
//	is a part of. It also defines main attributes that apply to every individual
//	manifest entry.  No attribute in this section can have its name equal to
//	"Name". This section is terminated by an empty line.
//
//	The individual sections define various attributes for packages or files
//	contained in this JAR file. Not all files in the JAR file need to be listed
//	in the manifest as entries, but all files which are to be signed must be
//	listed. The manifest file itself must not be listed.  Each section must
//	start with an attribute with the name as "Name", and the value must be
//	relative path to the file, or an absolute URL referencing data outside the
//	archive.
//
// This is contradicted by the example given and manifests seen in the wild, so
// don't trust that the newline exists between sections.
func newMainSectionReader(r io.Reader) io.Reader {
	buf := bufio.NewReader(r)
	end := bytes.NewReader([]byte("\r\n\r\n"))
	return io.MultiReader(&mainSectionReader{Reader: buf}, end)
}

type mainSectionReader struct {
	*bufio.Reader
}

var _ io.Reader = (*mainSectionReader)(nil)

// Read implements io.Reader.
func (m *mainSectionReader) Read(b []byte) (int, error) {
	if m.Reader == nil {
		return 0, io.EOF
	}
	n, err := m.Reader.Read(b)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, io.EOF):
		// Fall out and return the io.EOF to the caller.
	default:
		// Unknown error.
		return 0, err
	}
	b = b[:n]
	// Inspect for the end of the main section. If found, fuse the reader and
	// return EOF.
	if i := bytes.Index(b, []byte("\nName:")); i != -1 {
		// Account for dos line endings:
		if b[i-1] == '\r' {
			i--
		}
		b = b[:i]
		m.Reset(nil)
		m.Reader = nil
		err = io.EOF
	}

	return len(b), err
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
