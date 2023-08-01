package registry

import (
	"context"
	"net"
	"net/http"
)

// These are some common interfaces for plugins to optionally implement.
//
// Implementers can use blank assignments to check the interface is satisfied at
// compile time, and users can do a guarded type assertion to implement
// progressive enhancement.
type (
	// CanHTTP is implemented by plugins that expect access to an http client.
	//
	// The passed Client can be stored by the callee, but the Client should be
	// assumed to be shared. That is, it is unsafe to modify the Client and may
	// panic the program.
	CanHTTP interface {
		HTTPClient(context.Context, *http.Client) error
	}
	// CanDial is implemented by plugins that expect general network access.
	//
	// The passed Dialer can be stored by the callee, but the Dialer should be
	// assumed to be shared. That is, it is unsafe to modify the Dialer and may
	// panic the program.
	CanDial interface {
		NetDialer(context.Context, *net.Dialer) error
	}
)
