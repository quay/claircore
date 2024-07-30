package cpe

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer@latest
//go:generate stringer -type Attribute -linecomment
//go:generate stringer -type ValueKind
//go:generate stringer -type Relation -linecomment
//go:generate go run mkdict.go
