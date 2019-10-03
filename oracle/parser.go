package oracle

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"
)

var _ driver.Parser = (*Updater)(nil)

// Parse implements driver.Parser.
func (u *Updater) Parse(r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx := u.logger.WithContext(context.Background())
	// In tests, this takes at least 140 seconds. So, round up on the automatic
	// timeout.
	ctx, done := context.WithTimeout(ctx, 5*time.Minute)
	defer done()
	return u.ParseContext(ctx, r)
}

// ParseContext is like Parse, but with context.
func (u *Updater) ParseContext(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("oracle: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")

	return ovalutil.NewRPMInfo(&root).Extract(ctx)
}
