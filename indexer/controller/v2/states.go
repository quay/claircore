package controller

import (
	"container/heap"
	"context"
	"errors"
	"io"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/wart"
)

var _ = [...]stateFn{
	checkManifest,
	indexLayers,
	coalesce,
	indexManifest,
	manifestError,
	manifestFinished,
	loadManifest,
	((*plan)(nil)).Fetch,
	((*plan)(nil)).Index,
}

func checkManifest(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	const op = `checkManifest`
	defer stepCall.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(stepAttr(op))))
	ok, err := e.Store.ManifestScanned(ctx, m.Hash, e.Detectors)
	if err != nil {
		return nil, err
	}

	if ok {
		zlog.Info(ctx).Msg("manifest already scanned")
		return loadManifest, nil
	}

	// if we haven't seen this manifest, determine which scanners to use, persist it
	// and transition to FetchLayer state.
	zlog.Info(ctx).Msg("manifest to be scanned")

	// TODO(hank) Should add some API that reports this per-layer and doesn't
	// need loops like this.
	descs := wart.LayersToDescriptions(m.Layers)
	plan := plan{
		Reqs:  make([]layerRequest, len(descs)),
		Execs: make([]layerExec, len(descs)),
		N:     1, // TODO(hank) Make concurrency configurable.
	}
	for i, desc := range descs {
		p := &plan.Reqs[i]
		p.Desc = desc
		for _, det := range e.Detectors {
			d, err := claircore.ParseDigest(desc.Digest)
			if err != nil {
				return nil, newLayerError(desc.Digest, `digest parse failure`, err)
			}
			ok, err := e.Store.LayerScanned(ctx, d, det)
			if err != nil {
				return nil, newLayerError(desc.Digest, `layer existence lookup`, err)
			}
			if ok {
				continue
			}
			p.Detector = append(p.Detector, det)
		}
	}

	/*
		if err := e.Store.PersistManifest(ctx, *m); err != nil {
			return nil, fmt.Errorf("%s: failed to persist manifest: %w", op, err)
		}
	*/
	return plan.Fetch, nil

}

type plan struct {
	N     int
	Reqs  []layerRequest
	Execs []layerExec
}

func (p *plan) Fetch(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	const op = `fetch`
	h := execOrder(make([]workItem, len(p.Reqs)))
	for i := range h {
		h[i] = workItem{
			Req:   &p.Reqs[i],
			Exec:  &p.Execs[i],
			Index: -1,
		}
	}
	heap.Init(&h)
	zlog.Info(ctx).
		Interface("plan", h).
		Msg("planned execution")

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(p.N)
	for v := heap.Pop(&h); h.Len() > 0; v = heap.Pop(&h) {
		w := v.(workItem)
		d := w.Req.Desc.Digest
		ctx := zlog.ContextWithValues(ctx, "layer", d)
		select {
		case <-ctx.Done():
			zlog.Debug(ctx).
				Msg("context done")
			w.Exec.Err = newLayerError(d, op, context.Cause(ctx))
			continue
		default:
		}
		if len(w.Req.Detector) == 0 {
			zlog.Info(ctx).
				Msg("no fetch needed; skipping")
			continue
		}
		eg.Go(func() error {
			zlog.Warn(ctx).
				Msg("need to fetch; unimplemented")
			w.Exec.Err = newLayerError(d, op, errors.New("TODO"))
			return nil
		})
	}
	eg.Wait()

	errs := make([]error, len(p.Execs))
	for i, exec := range p.Execs {
		errs[i] = exec.Err
	}
	if err := errors.Join(errs...); err != nil {
		return nil, &stepError{
			durability: errKindTransient,
			inner:      err,
		}
	}

	return p.Index, nil
}

// ...
//
// This is overkill for the current use cases, but should allow easy
// modifications to the ordering logic later. If we had a size hint, ordering by
// detector-bytes seems like a way to reduce latency.
type execOrder []workItem

type workItem struct {
	Req   *layerRequest
	Exec  *layerExec
	Index int
}

// Len implements [heap.Interface].
func (q *execOrder) Len() int {
	return len(*q)
}

// Less implements [heap.Interface].
func (q *execOrder) Less(i int, j int) bool {
	a, b := (*q)[i].Req, (*q)[j].Req
	return len(a.Detector) < len(b.Detector)
}

// Pop implements [heap.Interface].
func (q *execOrder) Pop() any {
	s := *q
	n := len(s)
	p := s[n-1]
	s[n-1] = workItem{Index: -1}
	p.Index = -1
	*q = s[:n-1]
	return p
}

// Push implements [heap.Interface].
func (q *execOrder) Push(x any) {
	i := len(*q)
	p := x.(workItem)
	p.Index = i
	*q = append(*q, p)
}

// Swap implements [heap.Interface].
func (q *execOrder) Swap(i int, j int) {
	(*q)[i], (*q)[j] = (*q)[j], (*q)[i]
	(*q)[i].Index = i
	(*q)[j].Index = j
}

var _ heap.Interface = (*execOrder)(nil)

type layerRequest struct {
	Desc     claircore.LayerDescription
	Detector []detector
}

type layerExec struct {
	Cleanup io.Closer
	Err     error
	Layer   claircore.Layer
}

func (p *plan) Index(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	const op = `index`
	h := execOrder(make([]workItem, len(p.Reqs)))
	for i := range h {
		h[i] = workItem{
			Req:   &p.Reqs[i],
			Exec:  &p.Execs[i],
			Index: -1,
		}
	}
	heap.Init(&h)
	zlog.Info(ctx).
		Interface("plan", h).
		Msg("planned execution")

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(p.N)
	for v := heap.Pop(&h); h.Len() > 0; v = heap.Pop(&h) {
		w := v.(workItem)
		d := w.Req.Desc.Digest
		ctx := zlog.ContextWithValues(ctx, "layer", d)
		select {
		case <-ctx.Done():
			zlog.Debug(ctx).
				Msg("context done")
			w.Exec.Err = newLayerError(d, op, context.Cause(ctx))
			continue
		default:
		}
		if len(w.Req.Detector) == 0 {
			zlog.Info(ctx).
				Msg("no index needed; skipping")
			continue
		}
		eg.Go(func() error {
			zlog.Warn(ctx).
				Msg("need to index; unimplemented")
			w.Exec.Err = newLayerError(d, op, errors.New("TODO"))
			return nil
		})
	}
	eg.Wait()

	errs := make([]error, len(p.Execs))
	for i, exec := range p.Execs {
		errs[i] = exec.Err
	}
	if err := errors.Join(errs...); err != nil {
		return nil, &stepError{
			durability: errKindTransient,
			inner:      err,
		}
	}

	return nil, errors.New("TODO: next step")
}

func indexLayers(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}

func coalesce(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}

func indexManifest(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}

func manifestError(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}

func manifestFinished(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}

func loadManifest(ctx context.Context, e *exec, m *claircore.Manifest) (stateFn, error) {
	panic("unimplemented")
}
