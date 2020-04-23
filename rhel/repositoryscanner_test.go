package rhel

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
)

type FakeContainerAPICpeFetcher struct{}

func (fetcher *FakeContainerAPICpeFetcher) GetCPEs(nvr, arch string) ([]string, error) {
	if nvr == "rh-pkg-1-1" && arch == "x86_64" {
		return []string{
			"cpe:/o:redhat:enterprise_linux:8::computenode",
			"cpe:/o:redhat:enterprise_linux:8::baseos",
		}, nil
	}
	return []string{}, nil
}
func TestRepositoryScanner(t *testing.T) {
	table := []struct {
		name         string
		repositories []*claircore.Repository
		layerPath    string
	}{
		{
			name: "CPE-from-API",
			repositories: []*claircore.Repository{
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::computenode",
					Key:  "rhel-cpe-repo",
				},
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  "rhel-cpe-repo",
				},
			},
			layerPath: "testdata/layer-with-cpe.tar",
		},
		{
			name:         "No-cpe-info",
			repositories: nil,
			layerPath:    "testdata/layer-with-no-cpe-info.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := RepositoryScanner{&FakeContainerAPICpeFetcher{}}
			digest := claircore.Digest{}
			l := &claircore.Layer{
				Hash: digest,
			}
			l.SetLocal(tt.layerPath)
			repositories, err := scanner.Scan(context.Background(), l)
			if err != nil {
				t.Fail()
			}
			if !cmp.Equal(repositories, tt.repositories) {
				t.Fatalf("%v", cmp.Diff(repositories, tt.repositories))
			}
		})
	}
}
