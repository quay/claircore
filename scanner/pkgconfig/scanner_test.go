package pkgconfig

import (
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type scannerTestcase struct {
	File string
	Want pc
}

func (tc scannerTestcase) Run(t *testing.T) {
	t.Parallel()
	var got pc
	f, err := os.Open(tc.File)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := got.Scan(f); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}

func TestScanner(t *testing.T) {
	tt := []scannerTestcase{
		scannerTestcase{
			File: "testdata/bash-completion.pc",
			Want: pc{
				Name:    "bash-completion",
				Version: "2.8",
				URL:     "https://github.com/scop/bash-completion",
			},
		},
		scannerTestcase{
			File: "testdata/dracut.pc",
			Want: pc{
				Name:    "dracut",
				Version: "64fefc221cf13e858d4921be7f0b1eea86c364d2",
			},
		},
		scannerTestcase{
			File: "testdata/libpng.pc",
			Want: pc{Name: "libpng", Version: "1.6.37"},
		},
		scannerTestcase{
			File: "testdata/shared-mime-info.pc",
			Want: pc{Name: "shared-mime-info", Version: "1.15"},
		},
		scannerTestcase{
			File: "testdata/systemd.pc",
			Want: pc{
				Name:    "systemd",
				Version: "243",
				URL:     "https://www.freedesktop.org/wiki/Software/systemd",
			},
		},
		scannerTestcase{
			File: "testdata/udev.pc",
			Want: pc{Name: "udev", Version: "243"},
		},
	}

	for _, tc := range tt {
		t.Run(path.Base(tc.File), tc.Run)
	}
}
