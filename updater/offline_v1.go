package updater

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
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
			slog.WarnContext(ctx, "error closing config.json", "reason", err)
		}
	}()
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return err
	}

	us, err := u.updaters(ctx, cfg)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "got updaters", "count", len(us))

	spool, err := os.CreateTemp(tmpDir, tmpPattern)
	if err != nil {
		return err
	}
	defer func() {
		spoolname := spool.Name()
		if err := os.Remove(spoolname); err != nil {
			slog.WarnContext(ctx, "unable to remove spool file", "filename", spoolname, "reason", err)
		}
		if err := spool.Close(); err != nil {
			slog.WarnContext(ctx, "error closing spool file", "filename", spoolname, "reason", err)
		}
	}()

	for _, upd := range us {
		name := upd.Name
		fi, err := fs.Stat(sys, name)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			slog.InfoContext(ctx, "no import, skipping", "updater", name)
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
			slog.InfoContext(ctx, "updated vulnerabilites", "ref", ref)
		}
		if len(res.Enrichments) != 0 {
			if err := u.store.UpdateEnrichments(ctx, ref, name, fp, res.Enrichments); err != nil {
				return err
			}
			slog.InfoContext(ctx, "updated enrichments", "ref", ref)
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
	slog.InfoContext(ctx, "got updaters", "count", len(us))

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
	for range lim {
		// Worker goroutine.
		eg.Go(func() error {
			defer wg.Done()
			for upd := range feed {
				name := upd.Name
				log := slog.With("updater", name)
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
					log.WarnContext(ctx, "unable to create spool file", "reason", err)
					continue
				}
				spoolname := spool.Name()
				fp, err := u.fetchOne(ctx, upd, pfps[name], spool)
				if err != nil {
					if err := os.Remove(spoolname); err != nil {
						log.WarnContext(ctx, "unable to remove spool file", "filename", spoolname, "reason", err)
					}
					if err := spool.Close(); err != nil {
						log.WarnContext(ctx, "error closing spool file", "filename", spoolname, "reason", err)
					}
					log.InfoContext(ctx, "updater error", "reason", err)
					continue
				}
				if _, err := spool.Seek(0, io.SeekStart); err != nil {
					if err := os.Remove(spoolname); err != nil {
						log.WarnContext(ctx, "unable to remove spool file", "filename", spoolname, "reason", err)
					}
					if err := spool.Close(); err != nil {
						log.WarnContext(ctx, "error closing spool file", "filename", spoolname, "reason", err)
					}
					log.WarnContext(ctx, "unable to seek to start", "filename", spoolname, "reason", err)
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
			slog.WarnContext(ctx, "unable to remove fetch spool", "reason", err, "file", fn)
		}
		if err := r.spool.Close(); err != nil {
			slog.WarnContext(ctx, "unable to close fetch spool", "reason", err, "file", fn)
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
	slog.DebugContext(ctx, "wrote out fetch results", "ref", ref, "name", n)
	return nil
}

type result struct {
	spool *os.File
	fp    driver.Fingerprint
	name  string
}
