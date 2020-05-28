package driver

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/quay/claircore"
)

// Updater is an aggregate interface combining the method set of a Fetcher and a Parser
// and forces a Name() to be provided
type Updater interface {
	Name() string
	Fetcher
	Parser
}

// Parser is an interface which is embedded into the Updater interface.
//
// Parse should be called with an io.ReadCloser struct where the contents of a security
// advisory database can be read and parsed into an array of *claircore.Vulnerability
type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}

// Fetcher is an interface which is embedded into the Updater interface.
//
// When called the interface should determine if new security advisory data is available.
// Fingerprint may be passed into in order for the Fetcher to determine if the contents has changed
//
// If there is new content Fetcher should return a io.ReadCloser where the new content can be read.
// Optionally a fingerprint can be returned which uniquely identifies the new content.
//
// If the conent has not change an  Unchanged error should be returned.
type Fetcher interface {
	Fetch(context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
}

// Unchanged is returned by Fetchers when the database has not changed.
var Unchanged = errors.New("database contents unchanged")

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint string

// ConfigUnmarshaler can be thought of as an Unmarshal function with the byte
// slice provided, or a Decode function.
//
// The function should populate a passed struct with any configuration
// information.
type ConfigUnmarshaler func(interface{}) error

// Configurable is an interface that Updaters can implement to opt-in to having
// their configuration provided dynamically.
type Configurable interface {
	Configure(context.Context, ConfigUnmarshaler, *http.Client) error
}
