package ubuntu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		Name string
		Want *claircore.Distribution
	}{
		{
			// This is a Debian distribution.
			Name: "11",
			Want: nil,
		},
		{
			Name: "10.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "10.04",
				PrettyName:      "Ubuntu 10.04",
				VersionCodeName: "lucid",
				Version:         "10.04 (Lucid)",
			},
		},
		{
			Name: "12.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "12.04",
				PrettyName:      "Ubuntu 12.04",
				VersionCodeName: "precise",
				Version:         "12.04 (Precise)",
			},
		},
		{
			Name: "12.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "12.10",
				PrettyName:      "Ubuntu 12.10",
				VersionCodeName: "quantal",
				Version:         "12.10 (Quantal)",
			},
		},
		{
			Name: "13.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "13.04",
				PrettyName:      "Ubuntu 13.04",
				VersionCodeName: "raring",
				Version:         "13.04 (Raring)",
			},
		},
		{
			Name: "13.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "13.10",
				PrettyName:      "Ubuntu 13.10",
				VersionCodeName: "saucy",
				Version:         "13.10 (Saucy)",
			},
		},
		{
			Name: "14.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "14.04",
				PrettyName:      "Ubuntu 14.04",
				VersionCodeName: "trusty",
				Version:         "14.04 (Trusty)",
			},
		},
		{
			Name: "14.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "14.10",
				PrettyName:      "Ubuntu 14.10",
				VersionCodeName: "utopic",
				Version:         "14.10 (Utopic)",
			},
		},
		{
			Name: "15.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "15.04",
				PrettyName:      "Ubuntu 15.04",
				VersionCodeName: "vivid",
				Version:         "15.04 (Vivid)",
			},
		},
		{
			Name: "15.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "15.10",
				PrettyName:      "Ubuntu 15.10",
				VersionCodeName: "wily",
				Version:         "15.10 (Wily)",
			},
		},
		{
			Name: "16.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "16.04",
				PrettyName:      "Ubuntu 16.04",
				VersionCodeName: "xenial",
				Version:         "16.04 (Xenial)",
			},
		},
		{
			Name: "16.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "16.10",
				PrettyName:      "Ubuntu 16.10",
				VersionCodeName: "yakkety",
				Version:         "16.10 (Yakkety)",
			},
		},
		{
			Name: "17.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "17.04",
				PrettyName:      "Ubuntu 17.04",
				VersionCodeName: "zesty",
				Version:         "17.04 (Zesty)",
			},
		},
		{
			Name: "17.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "17.10",
				PrettyName:      "Ubuntu 17.10",
				VersionCodeName: "artful",
				Version:         "17.10 (Artful)",
			},
		},
		{
			Name: "18.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "18.04",
				PrettyName:      "Ubuntu 18.04",
				VersionCodeName: "bionic",
				Version:         "18.04 (Bionic)",
			},
		},
		{
			Name: "18.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "18.10",
				PrettyName:      "Ubuntu 18.10",
				VersionCodeName: "cosmic",
				Version:         "18.10 (Cosmic)",
			},
		},
		{
			Name: "19.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "19.04",
				PrettyName:      "Ubuntu 19.04",
				VersionCodeName: "disco",
				Version:         "19.04 (Disco)",
			},
		},
		{
			Name: "19.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "19.10",
				PrettyName:      "Ubuntu 19.10",
				VersionCodeName: "eoan",
				Version:         "19.10 (Eoan)",
			},
		},
		{
			Name: "20.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "20.04",
				PrettyName:      "Ubuntu 20.04",
				VersionCodeName: "focal",
				Version:         "20.04 (Focal)",
			},
		},
		{
			Name: "20.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "20.10",
				PrettyName:      "Ubuntu 20.10",
				VersionCodeName: "groovy",
				Version:         "20.10 (Groovy)",
			},
		},
		{
			Name: "21.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "21.04",
				PrettyName:      "Ubuntu 21.04",
				VersionCodeName: "hirsute",
				Version:         "21.04 (Hirsute)",
			},
		},
		{
			Name: "21.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "21.10",
				PrettyName:      "Ubuntu 21.10",
				VersionCodeName: "impish",
				Version:         "21.10 (Impish)",
			},
		},
		{
			Name: "22.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "22.04",
				PrettyName:      "Ubuntu 22.04",
				VersionCodeName: "jammy",
				Version:         "22.04 (Jammy)",
			},
		},
		{
			Name: "22.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "22.10",
				PrettyName:      "Ubuntu 22.10",
				VersionCodeName: "kinetic",
				Version:         "22.10 (Kinetic)",
			},
		},
		{
			Name: "23.04",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "23.04",
				PrettyName:      "Ubuntu 23.04",
				VersionCodeName: "lunar",
				Version:         "23.04 (Lunar)",
			},
		},
		{
			Name: "23.10",
			Want: &claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "23.10",
				PrettyName:      "Ubuntu 23.10",
				VersionCodeName: "mantic",
				Version:         "23.10 (Mantic)",
			},
		},
	}
	todo := make(map[string]struct{})
	ents, err := os.ReadDir("testdata/dist")
	if err != nil {
		t.Error(err)
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		todo[e.Name()] = struct{}{}
	}
	for _, tc := range table {
		t.Run(tc.Name, func(t *testing.T) {
			sys := os.DirFS(filepath.Join("testdata", "dist", tc.Name))
			got, err := findDist(sys)
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
		delete(todo, tc.Name)
	}
	if len(todo) != 0 {
		t.Errorf("missed directories: %v", todo)
	}
}
