package updater

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore/updater/driver/v1"
)

/*
This file implements the V1 import/export format, aka zip-of-zips.

The config is written to the root at "config.json", which should allow the Parse
step to ensure it has the same configuration parameters that the Fetch step did.

All Updaters created at the Fetch step have their data recorded in
subdirectories keyed by name.
*/

const exportV1 = `1`

func (u *Updater) importV1(ctx context.Context, sys fs.FS) error {
	var cfg driver.Configs
	f, err := sys.Open("config.json")
	if err != nil {
		return fmt.Errorf("updater import: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error closing config.json")
		}
	}()
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return err
	}

	us, err := u.updaters(ctx, cfg)
	if err != nil {
		return err
	}
	zlog.Info(ctx).
		Int("ct", len(us)).
		Msg("got updaters")

	spool, err := os.CreateTemp(tmpDir, tmpPattern)
	if err != nil {
		return err
	}
	defer func() {
		spoolname := spool.Name()
		if err := os.Remove(spoolname); err != nil {
			zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("unable to remove spool file")
		}
		if err := spool.Close(); err != nil {
			zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("error closing spool file")
		}
	}()

	for _, upd := range us {
		name := upd.Name
		ctx := zlog.ContextWithValues(ctx, "updater", name)
		fi, err := fs.Stat(sys, name)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			zlog.Info(ctx).
				Msg("no import, skipping")
			continue
		default:
			return err
		}
		if !fi.IsDir() {
			return errors.New("malformed input")
		}
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			return err
		}
		f, err := sys.Open(path.Join(name, `data`))
		if err != nil {
			return err
		}
		sz, err := io.Copy(spool, f)
		f.Close()
		if err != nil {
			return err
		}
		z, err := zip.NewReader(spool, sz)
		if err != nil {
			return err
		}

		res, err := u.parseOne(ctx, upd, z)
		if err != nil {
			return err
		}

		b, err := fs.ReadFile(sys, path.Join(name, `fingerprint`))
		if err != nil {
			return err
		}
		fp := driver.Fingerprint(b)

		var ref uuid.UUID
		b, err = fs.ReadFile(sys, path.Join(name, `ref`))
		if err != nil {
			return err
		}
		if err := ref.UnmarshalText(b); err != nil {
			return err
		}

		// Load into DB.
		if len(res.Vulnerabilities.Vulnerability) != 0 {
			if err := u.store.UpdateVulnerabilities(ctx, ref, name, fp, res.Vulnerabilities); err != nil {
				return err
			}
			zlog.Info(ctx).Stringer("ref", ref).Msg("updated vulnerabilites")
		}
		if len(res.Enrichments) != 0 {
			if err := u.store.UpdateEnrichments(ctx, ref, name, fp, res.Enrichments); err != nil {
				return err
			}
			zlog.Info(ctx).Stringer("ref", ref).Msg("updated enrichments")
		}
	}

	return nil
}

func (u *Updater) exportV1(ctx context.Context, z *zip.Writer, prev fs.FS) error {
	now := time.Now()

	w, err := z.CreateHeader(&zip.FileHeader{
		Name:     "config.json",
		Comment:  "updater configuration from the producer",
		Modified: now,
		Method:   zstdCompression,
	})
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(u.configs); err != nil {
		return err
	}

	us, err := u.updaters(ctx, u.configs)
	if err != nil {
		return err
	}
	zlog.Info(ctx).
		Int("ct", len(us)).
		Msg("got updaters")

	// WaitGroup for the worker goroutines.
	var wg sync.WaitGroup
	lim := runtime.GOMAXPROCS(0)
	wg.Add(lim)
	pfps := make(map[string]driver.Fingerprint)
	if prev != nil {
		walk := func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			dir, base := path.Split(p)
			if dir == "." || base != "fingerprint" {
				// Don't bother with anything that's not the fingerprint file.
				return nil
			}

			b, err := fs.ReadFile(prev, p)
			if err != nil {
				return err
			}
			pfps[dir] = driver.Fingerprint(b)
			return nil
		}
		if err := fs.WalkDir(prev, ".", walk); err != nil {
			return err
		}
	}
	// ErrGroup for the workers, feeder, and closer goroutines.
	eg, ctx := errgroup.WithContext(ctx)
	feed, res := make(chan taggedUpdater), make(chan *result)

	eg.Go(feeder(ctx, feed, us))
	// Closer goroutine.
	eg.Go(func() error {
		wg.Wait()
		close(res)
		return nil
	})
	eg.Go(func() error {
		// Collect results and write them out to the zip at "z".
		for r := range res {
			if err := addUpdater(ctx, z, now, r); err != nil {
				return err
			}
		}
		return nil
	})
	for i := 0; i < lim; i++ {
		// Worker goroutine.
		eg.Go(func() error {
			defer wg.Done()
			for upd := range feed {
				name := upd.Name
				ctx := zlog.ContextWithValues(ctx, "updater", name)
				// Zips have to be written serially, so we spool the fetcher
				// output to disk, then seek back to the start so it's ready to
				// read.
				//
				// Make sure to close the file in any error cases. The log
				// prints here use "info" for the application errors and "warn"
				// for the OS errors that really shouldn't be happening but we
				// can't do much to recover from.
				spool, err := os.CreateTemp(tmpDir, tmpPattern)
				if err != nil {
					zlog.Warn(ctx).Err(err).Msg("unable to create spool file")
					continue
				}
				spoolname := spool.Name()
				fp, err := u.fetchOne(ctx, upd, pfps[name], spool)
				if err != nil {
					if err := os.Remove(spoolname); err != nil {
						zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("unable to remove spool file")
					}
					if err := spool.Close(); err != nil {
						zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("error closing spool file")
					}
					zlog.Info(ctx).Err(err).Msg("updater error")
					continue
				}
				if _, err := spool.Seek(0, io.SeekStart); err != nil {
					if err := os.Remove(spoolname); err != nil {
						zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("unable to remove spool file")
					}
					if err := spool.Close(); err != nil {
						zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("error closing spool file")
					}
					zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("unable to seek to start")
					continue
				}
				res <- &result{
					fp:    fp,
					spool: spool,
					name:  name,
				}
			}
			return nil
		})
	}

	return eg.Wait()
}

// AddUpdater writes the results to the zip "z", recording it as time "now".
//
// This function assumes the result isn't in an error state.
func addUpdater(ctx context.Context, z *zip.Writer, now time.Time, r *result) error {
	defer func() {
		fn := r.spool.Name()
		if err := os.Remove(fn); err != nil {
			zlog.Warn(ctx).Err(err).Str("file", fn).Msg("unable to remove fetch spool")
		}
		if err := r.spool.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Str("file", fn).Msg("unable to close fetch spool")
		}
	}()
	n := r.name
	// Create a dir entry just to preserve filesystem semantics. Makes
	// things easier to use upon import.
	if _, err := z.Create(n + "/"); err != nil {
		return err
	}
	// Write Fingerprint
	w, err := z.CreateHeader(&zip.FileHeader{
		Name:     path.Join(n, `fingerprint`),
		Modified: now,
		Method:   zip.Deflate,
	})
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(r.fp)); err != nil {
		return err
	}
	// Write a ref
	w, err = z.CreateHeader(&zip.FileHeader{
		Name:     path.Join(n, `ref`),
		Modified: now,
		Method:   zip.Store,
	})
	if err != nil {
		return err
	}
	ref := uuid.New()
	b, err := ref.MarshalText()
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	// Write data
	w, err = z.CreateHeader(&zip.FileHeader{
		Name:     path.Join(n, `data`),
		Modified: now,
		Method:   zstdCompression,
	})
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r.spool); err != nil {
		return err
	}
	zlog.Debug(ctx).
		Stringer("ref", ref).
		Str("name", n).
		Msg("wrote out fetch results")
	return nil
}

type result struct {
	spool *os.File
	fp    driver.Fingerprint
	name  string
}
