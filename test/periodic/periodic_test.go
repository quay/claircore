package periodic

import (
	"flag"
	"net/http"
	"os"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
)

var (
	pkgClient = &http.Client{
		Transport: &http.Transport{},
	}

	fp driver.Fingerprint
)

func TestMain(m *testing.M) {
	enable := flag.Bool("enable", false, "enable tests")
	flag.Parse()
	if !*enable {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
