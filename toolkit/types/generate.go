package types

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -linecomment -output=generate_string.go -type=Severity,ArchOp,PackageKind
