package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	mock_datastore "github.com/quay/claircore/test/mock/datastore"
	mock_driver "github.com/quay/claircore/test/mock/driver"
	"github.com/quay/claircore/toolkit/events"
)

// TestEvent does just enough to test the event emitting bits.
func TestEvent(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mock_driver.NewMockMatcher(ctrl)
		ev := newEvent(m)
		got := ev.LogValue()
		want := slog.GroupValue(
			slog.Bool("remote", false),
			slog.Bool("dbfilter", false),
			slog.Bool("dbfilter_authoritative", false),
		)
		if !got.Equal(want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("NoHandler", func(t *testing.T) {
		// Cannot use the "test.Logging" helper because of an import cycle.
		ctx := t.Context()
		runMatchOne(t, ctx)
	})

	t.Run("MatchOne", func(t *testing.T) {
		var buf bytes.Buffer
		// Cannot use the "test.Logging" helper because of an import cycle.
		h := slog.NewJSONHandler(&buf, nil)
		ctx := events.WithHandler(t.Context(), h)
		runMatchOne(t, ctx)

		var evGot map[string]any
		dec := json.NewDecoder(&buf)
		dec.UseNumber()
		if err := dec.Decode(&evGot); err != nil {
			t.Errorf("decoding JSON: %v", err)
		}
		delete(evGot, slog.TimeKey)
		evWant := map[string]any{
			slog.LevelKey:   "INFO",
			slog.MessageKey: "match",
			matcherName: map[string]any{
				"dbfilter":               false,
				"dbfilter_authoritative": false,
				"remote":                 false,
				"interested":             json.Number("1"),
				"records":                json.Number("1"),
				"matched":                json.Number("0"),
				"vulnerabilities":        json.Number("0"),
			},
		}
		if !cmp.Equal(evGot, evWant) {
			t.Error(cmp.Diff(evGot, evWant))
		}
	})
}

const matcherName = "mockmatcher"

func runMatchOne(t *testing.T, ctx context.Context) {
	t.Helper()
	records := []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				ID:      "pkg1",
				Name:    "hello",
				Version: "1-1",
				Kind:    claircore.BINARY,
				Arch:    "amd64",
			},
			Distribution: &claircore.Distribution{
				ID:  "dist1",
				DID: "test",
			},
		},
	}

	ctrl := gomock.NewController(t)
	store := mock_datastore.NewMockVulnerability(ctrl)
	store.EXPECT().Get(
		gomock.Any(),
		gomock.AssignableToTypeOf([]*claircore.IndexRecord{}),
		gomock.AssignableToTypeOf(datastore.GetOpts{}),
	).Return(
		map[string][]*claircore.Vulnerability{}, nil,
	)

	m := mock_driver.NewMockMatcher(ctrl)
	m.EXPECT().Name().Return(matcherName)
	m.EXPECT().Query().Return([]driver.MatchConstraint{
		driver.DistributionDID,
	})
	m.EXPECT().Filter(records[0]).Return(true)

	got, err := matchOne(ctx, store, m, records)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want := map[string][]*claircore.Vulnerability{}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}

	if t.Failed() {
		t.FailNow()
	}
}
