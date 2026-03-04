package claircore

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -type=ArchOp -linecomment
//go:generate stringer -type=Severity
//go:generate stringer -type=PackageKind -linecomment
