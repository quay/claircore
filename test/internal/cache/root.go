//go:build go1.24

package cache

import "os"

// Root opens the specified cache directory as an [os.Root], creating
// directories as needed.
func Root(p ...string) (*os.Root, error) {
	dir, err := CheckedDirectory(p...)
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}
