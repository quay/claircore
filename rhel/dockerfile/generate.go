package dockerfile

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -type itemKind
//go:generate stringer -type varExpand -linecomment
