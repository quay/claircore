// Package java contains components for interrogating java packages in
// container layers.
package java

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"time"
	"unique"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/java/bom"
	"github.com/quay/claircore/java/jar"
	"github.com/quay/claircore/rpm"
	"github.com/quay/claircore/toolkit/types"
)

var (
	_ indexer.VersionedScanner   = (*Scanner)(nil)
	_ indexer.PackageScanner     = (*Scanner)(nil)
	_ indexer.RPCScanner         = (*Scanner)(nil)
	_ indexer.DefaultRepoScanner = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: "maven",
		URI:  "https://repo1.maven.apache.org/maven2",
	}
)

// DefaultSearchAPI is a maven-like REST API that may be used to do
// reverse lookups based on an archive's sha1 sum.
//
//doc:url indexer
const DefaultSearchAPI = `https://central.sonatype.com/solrsearch/select`
const DefaultRequestTimeout = 2 * time.Second

// ScannerConfig is the struct used to configure a Scanner.
type ScannerConfig struct {
	// DisableAPI disables the use of the API.
	DisableAPI bool `yaml:"disable_api" json:"disable_api"`
	// API is a URL endpoint to a maven-like REST API.
	// The default is DefaultSearchAPI.
	API               string        `yaml:"api" json:"api"`
	APIRequestTimeout time.Duration `yaml:"api_request_timeout" json:"api_request_timeout"`
}

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files that seem like jar, war or ear, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct {
	client             *http.Client
	root               *url.URL
	rootRequestTimeout time.Duration
}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "java" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "8" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Configure implements indexer.RPCScanner.
func (s *Scanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	var cfg ScannerConfig
	s.client = c
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.DisableAPI {
		slog.DebugContext(ctx, "search API disabled")
	} else {
		api := DefaultSearchAPI
		if cfg.API != "" {
			api = cfg.API
		}
		requestTimeout := DefaultRequestTimeout
		if cfg.APIRequestTimeout != 0 {
			requestTimeout = cfg.APIRequestTimeout
		}
		s.rootRequestTimeout = requestTimeout
		slog.DebugContext(ctx, "configured search API URL",
			"api", api,
			"requestTimeout", requestTimeout)
		u, err := url.Parse(api)
		if err != nil {
			return err
		}
		s.root = u
	}

	return nil
}

// Scan attempts to find jar, war or ear files and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (s *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("java: unable to open layer: %w", err)
	}

	// All used in the loop below.
	var ret []*claircore.Package
	buf := getBuf()
	h1, h256 := sha1.New(), sha256.New()
	hs := io.MultiWriter(h1, h256)
	ck1, ck256 := make([]byte, 0, sha1.Size), make([]byte, 0, sha256.Size)
	doSearch := s.root != nil
	defer putBuf(buf)
	set, err := rpm.NewPathSet(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("java: unable to check RPM db: %w", err)
	}
	seed := maphash.MakeSeed()
	sbomDup := make(map[uint64]struct{})
	sbomPath := make(map[uint64]struct{})
	sbomHash := map[unique.Handle[string]]map[uint64]struct{}{
		bom.HashSHA1:   make(map[uint64]struct{}),
		bom.HashSHA256: make(map[uint64]struct{}),
	}

	seq, walkErr := walkInteresting(ctx, sys)
	for k, p := range seq {
		log := slog.With("path", p)
		if set.Contains(p) {
			log.DebugContext(ctx, "file from an rpm")
			continue
		}

		h1.Reset()
		h256.Reset()
		buf.Reset()
		f, err := sys.Open(p)
		if err != nil {
			return nil, err
		}
		fStat, err := f.Stat()
		if err == nil {
			buf.Grow(int(fStat.Size()))
		}
		sz, err := buf.ReadFrom(io.TeeReader(f, hs))
		f.Close()
		if err != nil {
			return nil, err
		}
		rd := bytes.NewReader(buf.Bytes())

		switch k {
		case fileSBoM:
			dir := path.Dir(p)
			// Don't consume both compressed and uncompressed versions.
			//
			// This code doesn't prefer one or the other and assumes they're
			// equivalent.
			k := maphash.String(seed, dir)
			if _, ok := sbomDup[k]; ok {
				log.DebugContext(ctx, "skipping (assumed) duplicate SBoM")
				continue
			}
			sbomDup[k] = struct{}{}

			seq, err := bom.LoadCDX(ctx, rd)
			if err != nil {
				return nil, err
			}
			for bp, err := range seq {
				if err != nil {
					return nil, err
				}
				n := path.Join(dir, bp.Location)
				sbomPath[maphash.String(seed, n)] = struct{}{}
				for k, b := range bp.Hashes {
					h, ok := sbomHash[k]
					if !ok {
						continue
					}
					h[maphash.Bytes(seed, b)] = struct{}{}
				}
				var pkg claircore.Package
				if err := bom.PopulatePackage(&pkg, bp, p); err != nil {
					return nil, err
				}
				ret = append(ret, &pkg)
			}
		case fileJAR:
			// Let the zip reader determine if this is actually a valid zip file.
			// We cannot just check the header, as it's possible the jar file
			// starts off with a script. This scenario is explicitly mentioned in
			// the standard library: https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/archive/zip/reader.go;l=41.
			z, err := zip.NewReader(rd, sz)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, zip.ErrFormat):
				log.InfoContext(ctx, "not actually a jar: invalid zip", "reason", err)
				continue
			default:
				return nil, err
			}

			infos, err := jar.Parse(ctx, p, z)
			switch {
			case err == nil:
			case errors.Is(err, jar.ErrNotAJar):
				// Could not prove this is really a jar. Skip it and move on.
				log.InfoContext(ctx, "skipping jar", "reason", err)
				continue
			default:
				return nil, err
			}
			ck1 := h1.Sum(ck1)
			ck256 := h256.Sum(ck256)
			hex1, hex256 := hex.EncodeToString(ck1), hex.EncodeToString(ck256)
			ps := make([]*claircore.Package, len(infos))
			for j := range infos {
				i := &infos[j]
				// If we discovered a pom file, don't bother talking to the network.
				// If not, talk to the network if configured to do so.
				if !strings.HasSuffix(i.Source, "pom.properties") && doSearch {
					switch err := s.search(ctx, i, ck1); {
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
				pkg.Kind = types.BinaryPackage
				pkg.Filepath = p
				pkg.RepositoryHint = (url.Values{
					"hash": {
						"sha1:" + cmp.Or(hex.EncodeToString(i.SHA1), hex1),
						"sha256:" + cmp.Or(hex.EncodeToString(i.SHA256), hex256),
					},
				}).Encode()
				if i.CPE != nil {
					pkg.CPE = *i.CPE
				}
				// BUG(hank) There's probably some bugs lurking in the jar.Info →
				// claircore.Package mapping code around embedded jars. There's a
				// testcase to be written, there.

				idx := strings.LastIndex(i.Source, ":")
				// If the top-level JAR file can only be identified by its name,
				// i.Source will just be `.`
				// In this case, PackageDB should just be the filepath, n.
				// Otherwise, use i.Source.
				pkgDB := p
				if idx != -1 {
					pkgDB = i.Source[:idx]
				}
				// Only examine anything after the last colon (or the entire path if there is no colon).
				switch l := i.Source[idx+1:]; {
				case strings.HasSuffix(l, "pom.properties"):
					fallthrough
				case s.root != nil && i.Source == s.root.String():
					// Populate as a maven artifact.
					pkg.PackageDB = `maven:` + pkgDB
				case l == "META-INF/MANIFEST.MF":
					// information pulled from a manifest file
					pkg.PackageDB = `jar:` + pkgDB
				case l == ".":
					// Name guess.
					pkg.PackageDB = `file:` + pkgDB
				default:
					return nil, fmt.Errorf("java: martian Info: %+v", i)
				}
				ps[j] = &pkg
			}
			ret = append(ret, ps...)
		default:
			panic("unreachable")
		}
	}
	if err := walkErr(); err != nil {
		return nil, fmt.Errorf("java: walking fs: %w", err)
	}
	return ret, nil
}

// DefaultRepository implements [indexer.DefaultRepoScanner].
func (Scanner) DefaultRepository(ctx context.Context) *claircore.Repository {
	return &Repository
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
	if i.SHA1 != nil {
		ck = i.SHA1
	}
	success := false
	defer func() {
		searchCounter.WithLabelValues(strconv.FormatBool(success)).Inc()
	}()
	tctx, done := context.WithTimeout(ctx, s.rootRequestTimeout)
	defer done()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, s.root.String(), nil)
	if err != nil {
		slog.WarnContext(ctx, "unable to construct request", "reason", err)
		return errRPC
	}
	v := req.URL.Query()
	// 40 == 2 * sha1.Size. I don't there's a good way to keep it as
	// a constant.
	v.Set("q", fmt.Sprintf(`1:%40x`, ck))
	v.Set("wt", "json")
	req.URL.RawQuery = v.Encode()
	res, err := s.client.Do(req)
	if err != nil {
		slog.WarnContext(ctx, "error making request", "reason", err)
		return errRPC
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		slog.WarnContext(ctx, "unexpected response status", "status", res.Status)
		return errRPC
	}
	var sr searchResponse
	err = json.NewDecoder(res.Body).Decode(&sr)
	res.Body.Close()
	if err != nil {
		slog.WarnContext(ctx, "error decoding json", "reason", err)
		return errRPC
	}
	success = true
	if len(sr.Response.Doc) == 0 {
		slog.DebugContext(ctx, "no matching artifacts found")
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
