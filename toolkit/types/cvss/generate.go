package cvss

//go:generate go run ./internal/cmd/revlookup -o cvss_revlookup.go
//go:generate go run ./internal/cmd/v4data -o cvss_v4_score_data.go
//go:generate -command mkragel go run github.com/quay/claircore/toolkit/internal/cmd/mkragel
//go:generate mkragel cvss_v2_parse.rl
