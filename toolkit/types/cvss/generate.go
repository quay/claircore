package cvss

//go:generate go tool revlookup -o cvss_revlookup.go
//go:generate go tool v4data -o cvss_v4_score_data.go
//go:generate go tool mkragel cvss_v2_parse.rl cvss_v3_parse.rl cvss_v4_parse.rl
