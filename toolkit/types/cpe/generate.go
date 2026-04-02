package cpe

//go:generate go tool stringer -type Attribute -linecomment
//go:generate go tool stringer -type ValueKind
//go:generate go tool stringer -type Relation -linecomment
//go:generate go run mkdict.go
