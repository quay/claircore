package ruby_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/ruby"
)

func TestScanLocal(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	table := []struct {
		name      string
		total     int
		samples   []*claircore.Package
		layerPath string
	}{
		{
			name:  "simple Ruby layer",
			total: 6,
			samples: []*claircore.Package{
				{
					Name:           "bar",
					Version:        "0.0.2",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/bar-0.0.2.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "bundler",
					Version:        "2.4.7",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/lib/ruby/gems/3.2.0/specifications/default/bundler-2.4.7.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "foo",
					Version:        "0.0.1",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/foo-0.0.1-x86-mswin32.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rake",
					Version:        "13.0.6",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/rake-13.0.6.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rubyforge",
					Version:        "0.0.1",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/gems/rubygems-update-3.4.7/test/rubygems/specifications/rubyforge-0.0.1.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rubygems-update",
					Version:        "3.4.7",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/rubygems-update-3.4.7.gemspec",
					RepositoryHint: "rubygems",
				},
			},
			layerPath: "testdata/simple-ruby.tar",
		},
		{
			name:  "Ruby on Rails",
			total: 35,
			samples: []*claircore.Package{
				{
					Name:           "actioncable",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/actioncable-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "actionpack",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/actionpack-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "concurrent-ruby",
					Version:        "1.2.2",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/concurrent-ruby-1.2.2.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rails",
					Version:        "7.0.4.3",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/rails-7.0.4.3.gemspec",
					RepositoryHint: "rubygems",
				},
				{
					Name:           "rails-html-sanitizer",
					Version:        "1.5.0",
					Kind:           claircore.BINARY,
					PackageDB:      "usr/local/bundle/specifications/rails-html-sanitizer-1.5.0.gemspec",
					RepositoryHint: "rubygems",
				},
			},
			layerPath: "testdata/rails.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			scanner := &ruby.Scanner{}
			l := &claircore.Layer{}
			l.SetLocal(tt.layerPath)

			got, err := scanner.Scan(ctx, l)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(len(got), tt.total) {
				t.Error(cmp.Diff(len(got), tt.total))
			}

			gotMap := make(map[string]*claircore.Package, len(got))
			for _, pkg := range got {
				gotMap[pkg.Name] = pkg
			}

			for _, pkg := range tt.samples {
				gotPkg, exists := gotMap[pkg.Name]
				if !exists {
					t.Error(fmt.Sprintf("did not find %s", pkg.Name))
				}

				if !cmp.Equal(gotPkg, pkg) {
					t.Error(cmp.Diff(gotPkg, pkg))
				}
			}
		})
	}
}
