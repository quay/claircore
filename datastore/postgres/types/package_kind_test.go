package types

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/toolkit/types"
)

func TestPackageKind(t *testing.T) {
	t.Run("Scan", func(t *testing.T) {
		tcs := []struct {
			In   pgtype.Text
			Err  error
			Want PackageKind
		}{
			{
				In:   pgtype.Text{Valid: false},
				Want: PackageKind(types.UnknownPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: ""},
				Want: PackageKind(types.UnknownPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "invalid"},
				Want: PackageKind(types.UnknownPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "unknown"},
				Want: PackageKind(types.UnknownPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "source"},
				Want: PackageKind(types.SourcePackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "sOuRcE"},
				Want: PackageKind(types.SourcePackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "binary"},
				Want: PackageKind(types.BinaryPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "BiNaRy"},
				Want: PackageKind(types.BinaryPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "layer"},
				Want: PackageKind(types.LayerPackage),
			},
			{
				In:   pgtype.Text{Valid: true, String: "ancestry"},
				Want: PackageKind(types.AncestryPackage),
			},
		}

		for _, tc := range tcs {
			t.Run("", func(t *testing.T) {
				t.Logf("%#v ↦ %#v", tc.In, tc.Want)

				var got PackageKind
				err := got.ScanText(tc.In)
				if !errors.Is(err, tc.Err) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tc.Err)
				}
				if !cmp.Equal(got, tc.Want) {
					t.Error(cmp.Diff(got, tc.Want))
				}
			})
		}
	})

	t.Run("Value", func(t *testing.T) {
		tcs := []struct {
			In   PackageKind
			Err  error
			Want pgtype.Text
		}{
			{
				In:   PackageKind(types.UnknownPackage),
				Want: pgtype.Text{Valid: true, String: ""},
			},
			{
				In:   PackageKind(types.SourcePackage),
				Want: pgtype.Text{Valid: true, String: "source"},
			},
			{
				In:   PackageKind(types.BinaryPackage),
				Want: pgtype.Text{Valid: true, String: "binary"},
			},
		}

		for _, tc := range tcs {
			t.Run("", func(t *testing.T) {
				t.Logf("%#v ↦ %#v", tc.In, tc.Want)

				got, err := tc.In.TextValue()
				if !errors.Is(err, tc.Err) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tc.Err)
				}
				if !cmp.Equal(got, tc.Want) {
					t.Error(cmp.Diff(got, tc.Want))
				}
			})
		}
	})

	t.Run("WrapEncodePlan", func(t *testing.T) {
		for _, tc := range []struct {
			Name string
			In   any
		}{
			{"Value", types.PackageKind(0)},
			{"Pointer", new(types.PackageKind)},
		} {
			t.Run(tc.Name, func(t *testing.T) {
				p, v, ok := packageKindWrapEncodePlan(tc.In)
				if !ok {
					t.Error("expected wrapped encode plan returned")
				}
				if _, ok := p.(*wrapPackageKindEncodePlan); !ok {
					t.Errorf("got: %T, want: %T", p, new(*wrapPackageKindEncodePlan))
				}
				if _, ok := v.(PackageKind); !ok {
					t.Errorf("got: %T, want: %T", v, PackageKind(0))
				}
			})
		}
	})

	t.Run("WrapScanPlan", func(t *testing.T) {
		tgt := new(types.PackageKind)
		s, v, ok := packageKindWrapScanPlan(tgt)
		if !ok {
			t.Error("expected wrapped scan plan returned")
		}
		if _, ok := s.(*wrapPackageKindScanPlan); !ok {
			t.Errorf("got: %T, want: %T", s, new(*wrapPackageKindScanPlan))
		}
		if _, ok := v.(*PackageKind); !ok {
			t.Errorf("got: %T, want: %T", v, new(PackageKind))
		}
	})
}
