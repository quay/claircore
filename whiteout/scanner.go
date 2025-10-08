package whiteout

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	scannerName    = "whiteout"
	scannerVersion = "1"
	scannerKind    = "file"
)

var (
	_ indexer.FileScanner      = (*Scanner)(nil)
	_ indexer.VersionedScanner = (*Scanner)(nil)
)

type Scanner struct{}

func (*Scanner) Name() string { return scannerName }

func (*Scanner) Version() string { return scannerVersion }

func (*Scanner) Kind() string { return scannerKind }

func (s *Scanner) Scan(ctx context.Context, l *claircore.Layer) ([]claircore.File, error) {
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("whiteout: unable to create fs: %w", err)
	}
	wofs := []claircore.File{}
	err = fs.WalkDir(sys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".wh.") {
			cf := claircore.File{
				Path: path,
				Kind: claircore.FileKindWhiteout,
			}

			wofs = append(wofs, cf)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return wofs, nil
}
