package updater

import (
	"context"
	"io"
)

// Fetcher is an interface which is embedded into the Updater struct.
// When called the implementaiton should return an io.ReadCloser with
// contents of the target vulnerability data
type Fetcher interface {
	// Fetch should retrieve the target vulnerability data and return an io.ReadCloser
	// with the contents. Fetch should also return a string which can used to determine
	// if these contents should be applied to the vulnerability database. for example
	// a sha265 sum of a OVAL xml file.
	Fetch(context.Context) (io.ReadCloser, string, error)
}
