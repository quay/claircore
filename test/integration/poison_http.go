package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
)

func init() {
	http.DefaultTransport = poisonedTransport(`http.Transport`)
	http.DefaultClient = &http.Client{
		Transport: poisonedTransport(`http.Client`),
	}
}

func poisonedTransport(n string) *http.Transport {
	var dialer net.Dialer
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !skip() {
				return dialer.DialContext(ctx, network, addr)
			}
			cs := make([]uintptr, 10)
			skip := 2 // skip == 1 starts in this function, which is less useful than one would like.
			var pos string
		Stack:
			for {
				n := runtime.Callers(skip, cs)
				if n == 0 {
					break
				}
				cs := cs[:n]
				skip += len(cs)
				fs := runtime.CallersFrames(cs)
				for {
					f, more := fs.Next()
					if strings.Contains(f.Function, "claircore") {
						pos = fmt.Sprintf("%s:%d ", f.File, f.Line)
						break Stack
					}
					if !more {
						break Stack
					}
				}
			}
			const msg = `%sunable to dial %s!%s: default %s disallowed`
			return nil, fmt.Errorf(msg, pos, network, addr, n)
		},
	}
}
