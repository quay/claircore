package bodhi

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"time"

	"github.com/quay/zlog"

	driver "github.com/quay/claircore/updater/driver/v1"
)

var (
	_ driver.Updater             = (*Updater)(nil)
	_ driver.VulnerabilityParser = (*Updater)(nil)
)

// Updater ...
type Updater struct {
	root *url.URL
}

// Name implements driver.Updater.
func (u *Updater) Name() string { return fmt.Sprintf("bodhi/%s", u.root.Host) }

// Fingerprints are implemented with a type ending up as a JSON array for forward
// compatability. We currently just need a map[string]Time, but a dedicated entry
// type makes it possible to change this in the future.

type fingerprint map[string]time.Time

var (
	_ json.Marshaler   = (*fingerprint)(nil)
	_ json.Unmarshaler = (*fingerprint)(nil)
)

func (fp fingerprint) UnmarshalJSON(b []byte) error {
	var es []fpEntry
	if err := json.Unmarshal(b, &es); err != nil {
		return err
	}

	for _, e := range es {
		fp[e.Name] = e.Since
	}
	return nil
}

func (fp fingerprint) MarshalJSON() ([]byte, error) {
	es := make([]fpEntry, len(fp))
	i := 0
	for n, s := range fp {
		es[i].Name = n
		es[i].Since = s
		i++
	}
	sort.Slice(es, func(i, j int) bool {
		return es[i].Name < es[j].Name
	})
	return json.Marshal(es)
}

type fpEntry struct {
	Since time.Time `json:"since"`
	Name  string    `json:"name"`
}

// Fetch implements [driver.Updater].
func (u *Updater) Fetch(ctx context.Context, w *zip.Writer, prev driver.Fingerprint, c *http.Client) (driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "updater/bodhi/Updater.Fetch",
		"updater", u.Name(),
	)
	var nfp, fp fingerprint = make(map[string]time.Time), make(map[string]time.Time)
	if err := json.Unmarshal([]byte(prev), &fp); len(prev) != 0 && err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to make sense of previous fingerprint")
		prev = ""
	}
	bc := client{
		Root:   u.root,
		Client: c,
	}
	rs, err := bc.GetReleases(ctx)
	if err != nil {
		return prev, err
	}
	var todo []release
	for _, r := range rs {
		if r.Pending() {
			zlog.Debug(ctx).
				Stringer("release", r).
				Msg("release marked as pending, skipping")
			continue
		}
		todo = append(todo, r)
	}

	for _, r := range todo {
		if _, err := w.Create(r.Name + "/"); err != nil {
			return prev, fmt.Errorf("bodhi: unable to create file: %w", err)
		}
		f, err := w.Create(path.Join(r.Name, `release.json`))
		if err != nil {
			return prev, fmt.Errorf("bodhi: unable to create file: %w", err)
		}
		if err := json.NewEncoder(f).Encode(&r); err != nil {
			return prev, fmt.Errorf("bodhi: unable to create file: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return prev, fmt.Errorf("bodhi: error flushing output: %w", err)
	}

	now := time.Now()
	for _, r := range todo {
		more, err := bc.AnySince(ctx, &r, fp[r.Name])
		if err != nil {
			return prev, fmt.Errorf("bodhi: API error : %w", err)
		}
		if !more {
			continue
		}
		out, err := w.Create(path.Join(r.Name, "bodhi.json"))
		if err != nil {
			return prev, fmt.Errorf("bodhi: unable to create file: %w", err)
		}
		nfp[r.Name] = now
		if err := bc.Fetch(ctx, &r, out); err != nil {
			return prev, err
		}
	}
	if err := w.Flush(); err != nil {
		return prev, fmt.Errorf("bodhi: error flushing output: %w", err)
	}

	fpb, err := nfp.MarshalJSON()
	if err != nil {
		return prev, err
	}
	return driver.Fingerprint(string(fpb)), nil
}

// Parse implements driver.Updater.
func (u *Updater) ParseVulnerability(ctx context.Context, sys fs.FS) (*driver.ParsedVulnerabilities, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "updater/bodhi/Updater.Configure",
		"updater", u.Name(),
	)

	find := make(map[string]int)
	var todo []string
	err := fs.WalkDir(sys, ".", func(p string, ent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ent.IsDir() {
			return nil
		}
		d, f := path.Split(p)
		if d == "" || f == "" {
			return nil
		}
		if f == `release.json` || f == `bodhi.json` {
			find[d]++
		}
		if find[d] == 2 {
			todo = append(todo, path.Clean(d))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bodhi: error walking FS: %w", err)
	}
	zlog.Debug(ctx).Strs("releases", todo).Msg("found releases")

	ecs := newecs()
	for _, d := range todo {
		if err := ecs.LoadRelease(sys, d); err != nil {
			return nil, err
		}
	}

	return ecs.pv, nil
}

type ecs struct {
	Vulnerability map[uint64]int
	Package       map[uint64]int
	Distribution  map[uint64]int
	Repository    map[uint64]int

	mh maphash.Hash
	pv *driver.ParsedVulnerabilities
}

func newecs() *ecs {
	r := ecs{
		Vulnerability: make(map[uint64]int),
		Package:       make(map[uint64]int),
		Distribution:  make(map[uint64]int),
		Repository:    make(map[uint64]int),
		pv:            &driver.ParsedVulnerabilities{},
	}
	r.mh.Seed()
	return &r
}

func (e *ecs) LoadRelease(sys fs.FS, dir string) error {
	n := path.Join(dir, `release.json`)
	f, err := sys.Open(n)
	if err != nil {
		return fmt.Errorf("bodhi: error opening %q: %w", n, err)
	}
	defer f.Close()
	var r release
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return fmt.Errorf("bodhi: error unmarshaling %q: %w", n, err)
	}
	dist := e.loadDistribution(&r)
	_ = dist

	n = path.Join(dir, `bodhi.json`)
	f, err = sys.Open(n)
	if err != nil {
		return fmt.Errorf("bodhi: error opening %q: %w", n, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var u update
	for err = dec.Decode(&u); err == nil; err = dec.Decode(&u) {
		for _, b := range u.Builds {
			println(b.NVR, b.NEVR())
		}
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("bodhi: error unmarshaling %q: %w", n, err)
	}

	return nil
}

func (e *ecs) loadDistribution(r *release) int {
	e.mh.Reset()
	e.mh.WriteString(r.LongName)
	e.mh.WriteByte(0x00)
	e.mh.WriteString(r.Version)
	key := e.mh.Sum64()
	id, ok := e.Distribution[key]
	if !ok {
		id = len(e.pv.Distribution)
		e.pv.Distribution = append(e.pv.Distribution, driver.Distribution{
			ID:        r.LongName,
			VersionID: r.Version,
		})
		e.Distribution[key] = id
	}
	return id
}

func (e *ecs) loadPackage(b *build) int {
	e.mh.Reset()
	binary.Write(&e.mh, binary.LittleEndian, b.Epoch)
	e.mh.WriteByte(0x00)
	e.mh.WriteString(b.NVR)
	key := e.mh.Sum64()
	id, ok := e.Package[key]
	if !ok {
		id = len(e.pv.Package)
		e.pv.Package = append(e.pv.Package, driver.Package{})
		e.Package[key] = id
	}
	return id
}
