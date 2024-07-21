package main

//go:generate -command mkragel go run github.com/quay/claircore/toolkit/internal/cmd/mkragel
//go:generate mkragel parser.rl

// Need the reverse lookup table for the fragment parser.
//go:generate -command revlookup go run github.com/quay/claircore/toolkit/types/cvss/internal/cmd/revlookup
//go:generate revlookup -package main -version 4 -o revlookup.go
