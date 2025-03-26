// Package cache contains common functions and names for test caching.
package cache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// Name is the top-level cache directory name.
	Name = `clair-testing`

	// Layer is the layer cache directory name.
	Layer = `layer`
)

// Path constructs a local filesystem path by joining additional path segments
// "p" to the top-level cache directory.
//
// Only reports an error if [os.UserCacheDir] reports an error.
func Path(p ...string) (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return ".", fmt.Errorf("unable to determine user cache dir: %w", err)
	}

	return filepath.Join(append([]string{d, Name}, p...)...), nil
}

// CheckRoot checks that the root ("top-level") cache directory exists, creating
// it if needed.
func checkRoot() error {
	d, err := Path()
	if err != nil {
		return err
	}
	switch err := os.Mkdir(d, 0o755); {
	case errors.Is(err, nil): // Make cachedir tag
		p := filepath.Join(d, `CACHEDIR.TAG`)
		f, err := os.Create(p)
		if err != nil {
			// If we can't create this file, we're going to have a hell of a
			// time creating other ones.
			return fmt.Errorf("tried to create %q but failed: %w", p, err)
		}
		defer f.Close()
		if _, err := io.WriteString(f, cachedirtag); err != nil {
			return fmt.Errorf("error writing %q contents: %w", p, err)
		}
	case errors.Is(err, os.ErrExist): // Pre-existing
	default:
		return fmt.Errorf("unable to create test cache dir: %w", err)
	}
	return nil
}

const cachedirtag = `Signature: 8a477f597d28d172789f06886806bc55
# This file is a cache directory tag created for "github.com/quay/claircore" test data.
# For information about cache directory tags, see:
#	http://www.brynosaurus.com/cachedir/
`

// CheckedDirectory constructs a local filesystem path by joining additional
// path segments "p" to the top-level cache directory.
//
// Additionally, it attempts to create all needed directories to be able to
// create files under the returned path.
func CheckedDirectory(p ...string) (string, error) {
	if err := checkRoot(); err != nil {
		return ".", err
	}
	d, err := Path(p...)
	if err != nil {
		return ".", err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return ".", fmt.Errorf("unable to create cache dir %q: %w", d, err)
	}
	return d, nil
}
