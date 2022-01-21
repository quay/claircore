package driver

import (
	"context"
	"errors"
	"io/fs"
	"net/http"

	"github.com/quay/claircore"
)

// Scanner ...
//
// This type is named "Scanner" for historical reasons, despite what
// implementers do being called "indexing."
type Scanner interface {
	Name() string
	Version() string
	Init(context.Context, ConfigFunc) error
}

// ConfigFunc can be thought of as an Unmarshal function with the byte
// slice provided.
//
// This will typically be something like (*json.Decoder).Decode.
type ConfigFunc func(interface{}) error

// RemoteScanner should be implemented by any kind of scanner that expects to be
// able to talk to the network at index-time or in a background goroutine.
type RemoteScanner interface {
	InitRemote(context.Context, *http.Client) error
}

// ScannerDaemon should be implemented by any kind of scanner that needs
// background goroutine(s).
//
// The Daemon method will be called at initialization time and the provided
// Context will be cancelled at shutdown.
//
// If an error is reported before shutdown and the returned error matches
// ErrDaemonRestart, the method will be called again. Otherwise, the error will
// be logged and the Context cancelled.
type ScannerDaemon interface {
	Daemon(context.Context) error
}

// ErrDaemonRestart should be reported by a Daemon method when it is OK to be
// restarted.
var ErrDaemonRestart = errors.New("restart OK")

// LayerChange describes what kind of change happened where, and a more specific
// type for further information.
type LayerChange[T any] struct {
	Location string
	Op       ChangeOp
	Item     T
}

// ChangeOp indicates the kind of change in the layer.
type ChangeOp uint

const (
	// OpAdd indicates the Item was added.
	OpAdd ChangeOp = iota
	// OpRemove indicates the Item was removed. The OCI image spec has details
	// on how this is encoded.
	OpRemove
	// OpModify is specified because the OCI image spec says it's a
	// representable kind of change, but it is indistinguishable when encoded in
	// the specified "application/vnd.oci.image.layer.v1.tar".
	OpModify = OpAdd
)

type RepositoryIndexer interface {
	IndexRepository(context.Context, fs.FS) ([]LayerChange[claircore.Repository], error)
}

type DistributionIndexer interface {
	IndexDistribution(context.Context, fs.FS) ([]LayerChange[claircore.Distribution], error)
}

type PackageIndexer interface {
	IndexPackage(context.Context, fs.FS) ([]LayerChange[claircore.Package], error)
}
