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
		{
			Want: map[string]string{
				"architecture":             "x86_64",
				"build-date":               "2021-10-05T10:17:02.802845",
				"com.redhat.build-host":    "cpt-1007.osbs.prod.upshift.rdu2.redhat.com",
				"com.redhat.component":     "ubi7-container",
				"com.redhat.license_terms": "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
				"description":              "The Universal Base Image is designed and engineered to be the base layer for all of your containerized applications, middleware and utilities. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
				"distribution-scope":       "public",
				"io.k8s.description":       "The Universal Base Image is designed and engineered to be the base layer for all of your containerized applications, middleware and utilities. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
				"io.k8s.display-name":      "Red Hat Universal Base Image 7",
				"io.openshift.tags":        "base rhel7",
				"name":                     "ubi7",
				"release":                  "516",
				"summary":                  "Provides the latest release of the Red Hat Universal Base Image 7.",
				"url":                      "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi7/images/7.9-516",
				"vcs-ref":                  "a4e710a688a6374670ecdd56637c3f683d11cbe3",
				"vcs-type":                 "git",
				"vendor":                   "Red Hat, Inc.",
				"version":                  "7.9",
			},
			InFile: "Dockerfile-ubi7-7.9-516",
		},
		{
			Want: map[string]string{
				"architecture":                 "x86_64",
				"build-date":                   "2021-10-06T13:08:17.304497",
				"com.redhat.build-host":        "cpt-1005.osbs.prod.upshift.rdu2.redhat.com",
				"com.redhat.component":         "s2i-core-container",
				"com.redhat.license_terms":     "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
				"description":                  "The s2i-core image provides any images layered on top of it with all the tools needed to use source-to-image functionality while keeping the image size as small as possible.",
				"distribution-scope":           "public",
				"io.k8s.description":           "The s2i-core image provides any images layered on top of it with all the tools needed to use source-to-image functionality while keeping the image size as small as possible.",
				"io.k8s.display-name":          "s2i core",
				"io.openshift.s2i.scripts-url": "image:///usr/libexec/s2i",
				"io.s2i.scripts-url":           "image:///usr/libexec/s2i",
				"name":                         "rhscl/s2i-core-rhel7",
				"release":                      "235",
				"summary":                      "Base image which allows using of source-to-image.",
				"url":                          "https://access.redhat.com/containers/#/registry.access.redhat.com/rhscl/s2i-core-rhel7/images/1-235",
				"vcs-ref":                      "7fb31fe42247120f04b5e2d94f1719411f1037e8",
				"vcs-type":                     "git",
				"vendor":                       "Red Hat, Inc.",
				"version":                      "1",
			},
			InFile: "Dockerfile-rhscl-s2i-core-rhel7-1-235",
		},
		{
			Want: map[string]string{
				"architecture":                 "x86_64",
				"build-date":                   "2021-10-20T13:56:03.899740",
				"com.redhat.build-host":        "cpt-1007.osbs.prod.upshift.rdu2.redhat.com",
				"com.redhat.component":         "rh-redis5-container",
				"com.redhat.license_terms":     "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#rhel",
				"description":                  "Redis 5 available as container, is an advanced key-value store. It is often referred to as a data structure server since keys can contain strings, hashes, lists, sets and sorted sets. You can run atomic operations on these types, like appending to a string; incrementing the value in a hash; pushing to a list; computing set intersection, union and difference; or getting the member with highest ranking in a sorted set. In order to achieve its outstanding performance, Redis works with an in-memory dataset. Depending on your use case, you can persist it either by dumping the dataset to disk every once in a while, or by appending each command to a log.",
				"distribution-scope":           "public",
				"io.k8s.description":           "Redis 5 available as container, is an advanced key-value store. It is often referred to as a data structure server since keys can contain strings, hashes, lists, sets and sorted sets. You can run atomic operations on these types, like appending to a string; incrementing the value in a hash; pushing to a list; computing set intersection, union and difference; or getting the member with highest ranking in a sorted set. In order to achieve its outstanding performance, Redis works with an in-memory dataset. Depending on your use case, you can persist it either by dumping the dataset to disk every once in a while, or by appending each command to a log.",
				"io.k8s.display-name":          "Redis 5",
				"io.openshift.expose-services": "6379:redis",
				"io.openshift.tags":            "database,redis,redis5,rh-redis5",
				"maintainer":                   "SoftwareCollections.org <sclorg@redhat.com>",
				"name":                         "rhscl/redis-5-rhel7",
				"release":                      "53.1634738116",
				"summary":                      "Redis in-memory data structure store, used as database, cache and message broker",
				"url":                          "https://access.redhat.com/containers/#/registry.access.redhat.com/rhscl/redis-5-rhel7/images/5-53.1634738116",
				"usage":                        "podman run -d --name redis_database -p 6379:6379 rhscl/redis-5-rhel7",
				"vcs-ref":                      "1ca08b535089c4828147120ead2699d9f237260a",
				"vcs-type":                     "git",
				"vendor":                       "Red Hat, Inc.",
				"version":                      "5",
			},
			InFile: "Dockerfile-rhscl-redis-5-rhel7-5-53.1634738116",
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
