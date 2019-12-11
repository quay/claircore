package test

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/quay/goval-parser/oval"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

var _ driver.Updater = (*updater)(nil)

type updater struct {
	file string
}

func (u *updater) Name() string { return fmt.Sprintf("test-updater-%s", filepath.Base(u.file)) }

func (u *updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	var hint string
	f, err := os.Open(u.file)
	if f != nil {
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, driver.Fingerprint(hint), err
		}
		hint = fi.ModTime().Format(time.RFC3339)
	}
	return f, driver.Fingerprint(hint), err
}
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("test: unable to decode OVAL document: %w", err)
	}
	return ovalutil.NewRPMInfo(&root).Extract(ctx)
}

func Updater(file string) (driver.Updater, error) {
	return &updater{
		file: file,
	}, nil
}
