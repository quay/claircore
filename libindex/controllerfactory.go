package libindex

import (
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/indexer/controller"
)

// ControllerFactory is a factory method to return a Controller during libindex runtime.
type ControllerFactory func(opts *indexer.Options) *controller.Controller
