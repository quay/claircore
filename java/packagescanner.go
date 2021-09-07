// Package java contains components for interrogating java packages in
// container layers.
package java

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/trace"
	"sort"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/java/jar"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
	_ indexer.RPCScanner       = (*Scanner)(nil)
)

const DefaultSearchAPI = `https://search.maven.org/solrsearch/select`

// ScannerConfig is the struct used to configure a Scanner.
type ScannerConfig struct {
	// API is a URL endpoint to a maven-like REST API.
	// The default is DefaultSearchAPI.
	API string `yaml:"api" json:"api"`
}

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files that seem like jar, war or ear, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct {
	client *http.Client
	root   *url.URL
}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "java" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "3" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Configure implements indexer.RPCScanner.
func (s *Scanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "java/Scanner.Configure"),
		label.String("version", s.Version()))
	var cfg ScannerConfig
	s.client = c
	if err := f(&cfg); err != nil {
		return err
	}
	api := DefaultSearchAPI
	if cfg.API != "" {
		api = cfg.API
	}
	zlog.Debug(ctx).
		Str("api", api).
		Msg("configured search API URL")
	u, err := url.Parse(api)
	if err != nil {
		return err
	}
	s.root = u
	return nil
}

// Scan attempts to find jar, war or ear files and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (s *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "java/Scanner.Scan"),
		label.String("version", s.Version()),
		label.String("layer", layer.Hash.String()))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	tr := tar.NewReader(r)
	// All used in the loop below.
	var ret []*claircore.Package
	var h *tar.Header
	buf := getBuf()
	sh := sha1.New()
	ck := make([]byte, sha1.Size)
	doSearch := s.root != nil
	defer putBuf(buf)
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		// The minimum size of a zip archive is 22 bytes.
		if h.Size < jar.MinSize || !isArchive(ctx, h) {
			continue
		}

		sh.Reset()
		buf.Reset()
		// Calculate the SHA1 as it's buffered, since it may be needed for
		// searching later.
		sz, err := buf.ReadFrom(io.TeeReader(tr, sh))
		if err != nil {
			return nil, err
		}
		zb := buf.Bytes()
		if !bytes.Equal(zb[:4], jar.Header) {
			// Has a reasonable size and name, but isn't really a zip.
			zlog.Debug(ctx).Str("file", h.Name).Msg("not actually a jar: bad header")
			continue
		}
		z, err := zip.NewReader(bytes.NewReader(zb), sz)
		if err != nil {
			return nil, err
		}
		infos, err := jar.Parse(ctx, h.Name, z)
		if err != nil {
			return nil, err
		}
		sh.Sum(ck[:0])
		ps := make([]*claircore.Package, len(infos))
		for j := range infos {
			i := &infos[j]
			// If we discovered a pom file, don't bother talking to the network.
			// If not, talk to the network if configured to do so.
			if !strings.HasSuffix(i.Source, "pom.properties") && doSearch {
				switch err := s.search(ctx, i, ck); {
				case errors.Is(err, nil): // OK
				case errors.Is(err, errRPC):
				// BUG(hank) There's no way for a scanner that makes RPC calls
				// to signal "the call failed, these are best-effort results,
				// and please retry."
				default:
					return nil, err
				}
			}

			var pkg claircore.Package
			pkg.Name = i.Name
			pkg.Version = i.Version
			pkg.Kind = claircore.BINARY
			b := ck
			if len(i.SHA) != 0 {
				b = i.SHA
			}
			pkg.RepositoryHint = fmt.Sprintf(`sha1:%40x`, b)
			// BUG(hank) There's probably some bugs lurking in the jar.Info →
			// claircore.Package mapping code around embedded jars. There's a
			// testcase to be written, there.
			switch {
			case strings.HasSuffix(i.Source, "pom.properties") || (s.root != nil && i.Source == s.root.String()):
				// Populate as a maven artifact.
				pkg.PackageDB = `maven:` + h.Name
			case i.Source == "META-INF/MANIFEST.MF":
				// information pulled from a manifest file
				pkg.PackageDB = `jar:` + h.Name
			case i.Source == ".":
				// Name guess.
				pkg.PackageDB = `file:` + h.Name
			default:
				return nil, fmt.Errorf("java: martian Info: %+v", i)
			}
			ps[j] = &pkg
		}
		ret = append(ret, ps...)
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}

// Search attempts to search with the configured client and API endpoint.
//
// This function modifies the passed Info in-place if successful. The passed
// byte slice should be a SHA1 sum of the jar. It is used if the "SHA" member of
// the Info is not populated.
//
// ErrRPC is reported if anything went wrong making the request or reading the
// response.
func (s *Scanner) search(ctx context.Context, i *jar.Info, ck []byte) error {
	if i.SHA != nil {
		ck = i.SHA
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.root.String(), nil)
	if err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to construct request")
		return errRPC
	}
	v := req.URL.Query()
	// 40 == 2 * sha1.Size. I don't there's a good way to keep it as
	// a constant.
	v.Set("q", fmt.Sprintf(`1:"%40x"`, ck))
	v.Set("wt", "json")
	req.URL.RawQuery = v.Encode()
	res, err := s.client.Do(req)
	if err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("error making request")
		return errRPC
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		zlog.Warn(ctx).
			Str("status", res.Status).
			Msg("unexpected reponse status")
		return errRPC
	}
	var sr searchResponse
	err = json.NewDecoder(res.Body).Decode(&sr)
	res.Body.Close()
	if err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("error decoding json")
		return errRPC
	}
	if len(sr.Response.Doc) == 0 {
		zlog.Debug(ctx).Msg("no matching artifacts found")
		return nil
	}
	// Sort and then take the first one, because apparently the same
	// artifact is uploaded under different names sometimes?
	sort.SliceStable(sr.Response.Doc, func(i, j int) bool {
		return sr.Response.Doc[i].ID < sr.Response.Doc[j].ID
	})
	i.Source = s.root.String()
	d := &sr.Response.Doc[0]
	i.Version = d.Version
	i.Name = d.Group + ":" + d.Artifact
	return nil
}

var errRPC = errors.New("search rpc failed")

// SearchResponse is the response from maven.
//
// Created by eyeballing the response from
// https://search.maven.org/solrsearch/select?q=1:%2235379fb6526fd019f331542b4e9ae2e566c57933%22&wt=json
type searchResponse struct {
	Response struct {
		Doc []struct {
			ID         string `json:"id"`
			Group      string `json:"g"`
			Artifact   string `json:"a"`
			Version    string `json:"v"`
			Classifier string `json:"p"`
		} `json:"docs"`
	} `json:"response"`
}
