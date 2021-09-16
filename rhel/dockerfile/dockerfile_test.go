package dockerfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetLabels(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		Want   map[string]string
		InFile string
	}{
		{
			Want: map[string]string{
				"architecture":                 "x86_64",
				"build-date":                   "2021-08-03T16:57:21.054109",
				"com.redhat.build-host":        "cpt-1002.osbs.prod.upshift.rdu2.redhat.com",
				"distribution-scope":           "public",
				"io.k8s.description":           "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
				"release":                      "208",
				"url":                          "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.4-208",
				"vcs-ref":                      "7256039d3c371a38cf13906dcf5688c19700c73b",
				"vcs-type":                     "git",
				"vendor":                       "Red Hat, Inc.",
				"com.redhat.component":         "ubi8-minimal-container",
				"com.redhat.license_terms":     "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
				"description":                  "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
				"io.k8s.display-name":          "Red Hat Universal Base Image 8 Minimal",
				"io.openshift.expose-services": "",
				"io.openshift.tags":            "minimal rhel8",
				"maintainer":                   "Red Hat, Inc.",
				"name":                         "ubi8-minimal",
				"summary":                      "Provides the latest release of the minimal Red Hat Universal Base Image 8.",
				"version":                      "8.4",
			},
			InFile: "Dockerfile-ubi8-minimal-8.4-208",
		},
	} {
		t.Run(tc.InFile, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tc.InFile))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := GetLabels(ctx, f)
			if err != nil {
				t.Error(err)
			}
			if want := tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func TestSplit(t *testing.T) {
	for _, p := range []struct {
		In   string
		Want []string
	}{
		{
			In:   "",
			Want: nil,
		},
		{
			In:   "k=v",
			Want: []string{"k=v"},
		},
		{
			In:   `k=v\ v`,
			Want: []string{`k=v\ v`},
		},
		{
			In:   `k=v k=v k=v`,
			Want: []string{`k=v`, `k=v`, `k=v`},
		},
		{
			In:   `k=" v "`,
			Want: []string{`k=" v "`},
		},
		{
			In:   `k=' v '`,
			Want: []string{`k=' v '`},
		},
		{
			In:   `k=' v ' k="   "`,
			Want: []string{`k=' v '`, `k="   "`},
		},
		{
			In: "k=' v '	\v k=\"   \"",
			Want: []string{`k=' v '`, `k="   "`},
		},
	} {
		t.Logf("input: %#q", p.In)
		got, err := splitKV('\\', p.In)
		if err != nil {
			t.Error(err)
		}
		if want := p.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
