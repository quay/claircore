//go:build tools

package claircore

import (
	_ "github.com/golang/mock/mockgen"
	_ "golang.org/x/tools/cmd/file2fuzz"
	_ "golang.org/x/tools/cmd/stringer"
)
