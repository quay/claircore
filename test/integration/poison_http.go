package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

func init() {
	if !skip {
		return
	}
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			const msg = `unable to dial %s!%s: DefaultTransport disallowed`
			return nil, fmt.Errorf(msg, network, addr)
		},
	}
}
