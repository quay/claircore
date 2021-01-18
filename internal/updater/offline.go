package updater

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"runtime"
	"sync"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
)

// Offline is a controller for running Updaters in an offline matter.
type Offline struct {
	// Output is used as the sink for calls to Run.
	//
	// A call to Run will write gzipped json objects to the Writer.
	// See the 'jsonblob' package for the details of the json format.
	//
	// This package does not take care of any framing for the writer.
	// If Run is called multiple times, this member should be reset accordingly.
	// That is, calling run multiple times with the same writer will result in
	// concatenated gzip blobs.
	Output io.Writer

	// If the Filter member is provided, the updater set's names will be passed
	// through it.
	Filter func(name string) (keep bool)
}

var _ Controller = (*Offline)(nil)

// Run implements Controller.
//
// Run does no synchronization around the configured Writer. Returned results
// are always written, even if an error is ultimately returned from this
// function.
func (o *Offline) Run(ctx context.Context, ch <-chan driver.Updater) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/updater/Offline"))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	filter := func(_ string) bool { return true }
	if f := o.Filter; f != nil {
		filter = f
	}
	w := runtime.NumCPU() * 2

	store, err := jsonblob.New()
	if err != nil {
		return err
	}
	errs := &errmap{m: make(map[string]error)}
	var wg sync.WaitGroup
	wg.Add(w)
	for i := 0; i < w; i++ {
		go func() {
			defer wg.Done()
			var u driver.Updater
			var ok bool
			for {
				select {
				case <-ctx.Done():
				case u, ok = <-ch:
					if !ok {
						return
					}
				}

				name := u.Name()
				ctx := baggage.ContextWithValues(ctx,
					label.String("updater", name))

				if !filter(name) {
					zlog.Debug(ctx).Msg("filtered")
					continue
				}

				if err := driveUpdater(ctx, u, store); err != nil {
					errs.add(name, err)
				}
			}
		}()
	}
	wg.Wait()

	bw := bufio.NewWriter(o.Output)
	gz := gzip.NewWriter(bw)
	defer func() {
		gz.Close()
		bw.Flush()
	}()
	if err := store.Store(gz); err != nil {
		errs.add("jsonblob", err)
	}

	if errs.len() != 0 {
		return errs.error()
	}
	return nil
}
