//go:build tools

package claircore

import (
	_ "go.uber.org/mock/mockgen"
	_ "golang.org/x/tools/cmd/file2fuzz"
	_ "golang.org/x/tools/cmd/stringer"
)
