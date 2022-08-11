package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

func TestController(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	t.Run("New", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ctl := gomock.NewController(t)
		ir := new(claircore.IndexReport)
		store := indexer.NewMockStore(ctl)
		store.EXPECT().
			ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(1).
			Return(true, nil)
		store.EXPECT().
			IndexReport(gomock.Any(), gomock.Any()).
			Times(1).
			Return(ir, true, nil)
		store.EXPECT().
			SetIndexReport(gomock.Any(), ir).
			Times(1).
			Return(nil)
		r := indexer.NewMockRealizer(ctl)
		r.EXPECT().
			Close().
			Times(1).
			Return(nil)

		m := claircore.Manifest{}
		opt := Options{
			Store: store,
			Realizer: func(_ context.Context) (indexer.Realizer, error) {
				return r, nil
			},
			Limit: 1,
		}
		c, err := New(opt)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		got, err := c.Index(ctx, &m)
		if err != nil {
			t.Error(err)
		}
		_ = got
	})
	t.Run("Cancelled", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ctl := gomock.NewController(t)
		ir := new(claircore.IndexReport)
		cctx, cancel := context.WithCancel(ctx)
		store := indexer.NewMockStore(ctl)
		store.EXPECT().
			ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(1).
			Return(true, nil)
		store.EXPECT().
			IndexReport(gomock.Any(), gomock.Any()).
			Times(1).
			Do(func(interface{}, interface{}) {
				cancel()
			}).
			Return(ir, true, nil)
		store.EXPECT().
			SetIndexReport(gomock.Any(), ir).
			Times(0).
			Return(nil)
		r := indexer.NewMockRealizer(ctl)
		r.EXPECT().
			Close().
			Times(1).
			Return(nil)

		m := claircore.Manifest{}
		opt := Options{
			Store: store,
			Realizer: func(_ context.Context) (indexer.Realizer, error) {
				return r, nil
			},
			Limit: 1,
		}
		c, err := New(opt)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		got, err := c.Index(cctx, &m)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got: %v, want: %v", err, context.Canceled)
		}
		_ = got
	})
}
