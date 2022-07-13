package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

type LayerIndexer struct {
	sem      *semaphore.Weighted
	perIndex int64

	ps []indexer.PackageScanner
	ds []indexer.DistributionScanner
	rs []indexer.RepositoryScanner
}

func NewLayerIndexer() (*LayerIndexer, error) {
	return nil, nil
}

type IndexRequest struct {
	Manifest claircore.Digest
	Layer    []*claircore.Layer
	Content  []claircore.ReadAtCloser
}

type IndexOption uint

const (
	_ IndexOption = iota
	OptionSkipCache
	OptionSkipStore
)

func (l *LayerIndexer) Index(ctx context.Context, req *IndexRequest, opts ...IndexOption) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "indexer/controller/LayerIndexer.Index",
		"manifest", req.Manifest.String())
	if err := l.sem.Acquire(ctx, l.perIndex); err != nil {
		return fmt.Errorf("layerindexer: %w", err)
	}
	defer l.sem.Release(l.perIndex)
	wsem := semaphore.NewWeighted(l.perIndex)

	fses := make([]*tarfs.FS, len(req.Content))
	fsErr := make([]error, len(req.Content))
	for i := range req.Content {
		go func(i int) {
			if err := wsem.Acquire(ctx, 1); err != nil {
				fsErr[i] = err
				return
			}
			fses[i], fsErr[i] = tarfs.New(req.Content[i])
			wsem.Release(1)
		}(i)
	}
	var es errSlice
	for _, e := range fsErr {
		es = append(es, e)
	}
	if es != nil {
		return es
	}

	eg, ctx := errgroup.WithContext(ctx)

	// ...

	var ie indexError
	ie.Inner = eg.Wait()
	for i, c := range req.Content {
		if err := c.Close(); err != nil {
			ie.Close = append(ie.Close, closeError{
				Err:   err,
				Which: req.Layer[i].Hash.String(),
			})
		}
	}
	if !ie.empty() {
		return &ie
	}
	return nil
}

type errSlice []error

func (es errSlice) Error() string {
	return ""
}

func (es errSlice) Unwrap() error {
	if len(es) > 1 {
		return es[1:]
	}
	return nil
}
func (es errSlice) Is(tgt error) bool {
	return len(es) > 0 && errors.Is(es[0], tgt)
}

type indexError struct {
	Inner error
	Close []closeError
}

type closeError struct {
	Which string
	Err   error
}

func (e *indexError) empty() bool {
	return errors.Is(e.Inner, nil) && len(e.Close) == 0
}

func (e *indexError) Error() string {
	var b strings.Builder
	orig, close := !errors.Is(e.Inner, nil), len(e.Close) != 0
	if orig {
		b.WriteString(e.Inner.Error())
	}
	if orig && close {
		b.WriteString(" (while closing layer contents:")
	}
	for i, cl := range e.Close {
		if i != 0 {
			b.WriteByte(';')
		}
		b.WriteByte(' ')
		b.WriteString(cl.Which)
		b.WriteString(": ")
		b.WriteString(cl.Err.Error())
	}
	if orig && close {
		b.WriteByte(')')
	}
	return b.String()
}

func (e *indexError) Unwrap() error {
	return e.Inner
}
