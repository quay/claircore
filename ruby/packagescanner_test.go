package ruby_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/ruby"
	"github.com/quay/claircore/test"
)

func TestScanRemote(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	type testcase struct {
		Name   string
		Ref    test.LayerRef
		Total  int
		Subset []*claircore.Package
	}
	table := []testcase{
		{
			// From the ruby-3.2.1-rake tag.
			Name: "Rake",
			Ref: test.LayerRef{
				Registry: "quay.io",
				Name:     "projectquay/clair-fixtures",
				Digest:   "sha256:f5da3e7f188aa027cf5c8111497d2abda6339d44eb0e7bff04647198ddfd87c1",
			},
			Total: 6,
			Subset: []*claircore.Package{
				{
					Name:           "bar",
					Version:        "0.0.2",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/bar-0.0.2.gemspec",
					Filepath:       "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/bar-0.0.2.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "bundler",
					Version:        "2.4.7",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/lib/ruby/gems/3.2.0/specifications/default/bundler-2.4.7.gemspec",
					Filepath:       "usr/local/lib/ruby/gems/3.2.0/specifications/default/bundler-2.4.7.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "foo",
					Version:        "0.0.1",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/foo-0.0.1-x86-mswin32.gemspec",
					Filepath:       "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/foo-0.0.1-x86-mswin32.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rake",
					Version:        "13.0.6",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/rake-13.0.6.gemspec",
					Filepath:       "usr/local/bundle/specifications/rake-13.0.6.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rubyforge",
					Version:        "0.0.1",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/rubyforge-0.0.1.gemspec",
					Filepath:       "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/rubyforge-0.0.1.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rubygems-update",
					Version:        "3.4.7",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/rubygems-update-3.4.7.gemspec",
					Filepath:       "usr/local/bundle/specifications/rubygems-update-3.4.7.gemspec",
					RepositoryHint: "rubygems",
				},
			},
		},
		{
			// From the "ruby-3.2.1-rails" tag.
			Name: "Rails",
			Ref: test.LayerRef{
				Registry: "quay.io",
				Name:     "projectquay/clair-fixtures",
				Digest:   "sha256:8cf469d41e77c8c4aaa2191f42f55b9758f77c640f2f7015b799b26458903f9b",
			},
			Total: 35,
			Subset: []*claircore.Package{
				{
					Name:           "actioncable",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/actioncable-7.0.4.3.gemspec",
					Filepath:       "usr/local/bundle/specifications/actioncable-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "actionpack",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/actionpack-7.0.4.3.gemspec",
					Filepath:       "usr/local/bundle/specifications/actionpack-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "concurrent-ruby",
					Version:        "1.2.2",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/concurrent-ruby-1.2.2.gemspec",
					Filepath:       "usr/local/bundle/specifications/concurrent-ruby-1.2.2.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rails",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/rails-7.0.4.3.gemspec",
					Filepath:       "usr/local/bundle/specifications/rails-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rails-html-sanitizer",
					Version:        "1.5.0",
					Kind:           claircore.BINARY,
					PackageDB:      "ruby:usr/local/bundle/specifications/rails-html-sanitizer-1.5.0.gemspec",
					Filepath:       "usr/local/bundle/specifications/rails-html-sanitizer-1.5.0.gemspec",
					RepositoryHint: "rubygems",
				},
			},
		},
	}

	for _, tc := range table {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			l := test.RealizeLayer(ctx, t, tc.Ref)
			var scanner ruby.Scanner

			got, err := scanner.Scan(ctx, l)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(len(got), tc.Total) {
				t.Error(cmp.Diff(len(got), tc.Total))
			}

			gotMap := make(map[string]*claircore.Package, len(got))
			for _, pkg := range got {
				gotMap[pkg.Name] = pkg
			}

			for _, pkg := range tc.Subset {
				gotPkg, exists := gotMap[pkg.Name]
				if !exists {
					t.Errorf("did not find %s", pkg.Name)
				}

				if !cmp.Equal(gotPkg, pkg) {
					t.Error(cmp.Diff(gotPkg, pkg))
				}
			}
		})
	}
}
