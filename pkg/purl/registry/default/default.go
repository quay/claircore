package defaults

import (
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/pkg/purl"
	"github.com/quay/claircore/rhel"
)

// New constructs a registry pre-registered with built-in generators and parsers.
// Callers must explicitly invoke this to obtain a wired registry.
func New() *purl.Registry {
	r := purl.NewRegistry()
	r.RegisterScanner(gobin.Detector{}, gobin.GeneratePURL)
	r.RegisterScanner(rhel.PackageScanner{}, rhel.GenerateRPMPURL)
	r.RegisterPurlType(gobin.PURLType, purl.NoneNamespace, gobin.ParsePURL)
	r.RegisterPurlType(rhel.PURLType, rhel.PURLNamespace, rhel.ParseRPMPURL)
	return r
}
