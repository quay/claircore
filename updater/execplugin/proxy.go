package execupdater

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
)

func newProxy(ctx context.Context, c *http.Client) (*proxy, error) {
	l, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		return nil, err
	}
	p := proxy{
		c:    c,
		Addr: `http://` + l.Addr().String(),
	}
	p.srv = &http.Server{
		Handler: &p,
	}
	go p.srv.Serve(l)
	return &p, nil
}

type proxy struct {
	d    net.Dialer
	c    *http.Client
	srv  *http.Server
	Addr string
}

func (p *proxy) Close() error {
	return p.srv.Close()
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method == http.MethodConnect {
		// See https://httpwg.org/specs/rfc7231.html#CONNECT
		h, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f, ok := w.(http.Flusher)
		if !ok {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Any 2xx (Successful) response indicates that the sender (and all
		// inbound proxies) will switch to tunnel mode immediately after the
		// blank line that concludes the successful response's header section;
		// data received after that blank line is from the server identified by
		// the request-target.
		//
		// A server MUST NOT send any Transfer-Encoding or Content-Length header
		// fields in a 2xx (Successful) response to CONNECT.
		w.Header()[`Transfer-Encoding`] = nil
		w.Header()[`Content-Length`] = nil
		w.WriteHeader(http.StatusOK)
		f.Flush()
		conn, buf, err := h.Hijack()
		if err != nil {
			zlog.Warn(ctx).Err(err).Msg("???")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		p.connect(ctx, conn, buf, r.RequestURI)
		return
	}
	// req := r.Clone(ctx)
	panic("TODO")
}

func (p *proxy) connect(ctx context.Context, ic net.Conn, buf *bufio.ReadWriter, hp string) {
	defer ic.Close()
	conn, err := p.d.DialContext(ctx, "tcp", hp)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, context.Canceled):
		return
	default:
		zlog.Info(ctx).Err(err).Msg("error proxying CONNECT")
		return
	}
	defer conn.Close()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { // egress
		for {
			_, err := io.CopyN(conn, buf, 4096)
			switch {
			case errors.Is(err, nil):
				fallthrough
			case errors.Is(err, os.ErrDeadlineExceeded):
				// Push out the deadlines.
				d := time.Now().Add(2 * time.Second)
				ic.SetReadDeadline(d)
				conn.SetWriteDeadline(d)
			case errors.Is(err, io.EOF):
				return nil
			default:
				//???
				return err
			}
		}
	})
	eg.Go(func() error { // ingress
		const flush = time.Second * 2
		for {
			_, err := io.CopyN(buf, conn, 4096)
			buf.Flush() // log?
			switch {
			case errors.Is(err, nil):
				fallthrough
			case errors.Is(err, os.ErrDeadlineExceeded):
				// Push out the deadlines.
				d := time.Now().Add(flush)
				ic.SetWriteDeadline(d)
				conn.SetReadDeadline(d)
			case errors.Is(err, io.EOF):
				return nil
			default:
				//???
				return err
			}
		}
	})
	switch err := eg.Wait(); {
	case errors.Is(err, nil):
	case errors.Is(err, context.Canceled):
	default:
		zlog.Info(ctx).Err(err).Msg("error proxying CONNECT")
	}
}
