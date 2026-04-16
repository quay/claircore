module github.com/quay/claircore/toolkit

go 1.25.0

require (
	github.com/google/go-cmp v0.7.0
	github.com/package-url/packageurl-go v0.1.5
	golang.org/x/tools v0.44.0
)

require (
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)

tool (
	github.com/quay/claircore/toolkit/internal/cmd/cpedict
	github.com/quay/claircore/toolkit/internal/cmd/mkragel
	github.com/quay/claircore/toolkit/types/cvss/internal/cmd/revlookup
	github.com/quay/claircore/toolkit/types/cvss/internal/cmd/v4data
	golang.org/x/tools/cmd/stringer
)
