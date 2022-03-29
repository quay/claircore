package execupdater

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/quay/claircore/updater/driver/v1"
	"github.com/quay/zlog"
	"golang.org/x/exp/jsonrpc2"
)

// ExecConfig ...
//
// Known capabilities are:
// - parse_vulnerbilities
// - parse_enrichments
// - header_framing
type ExecConfig struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

type rpcv1Fetch struct {
	c     *http.Client
	async context.Context
	root  string
	prev  driver.Fingerprint

	mu  sync.Mutex
	w   *zip.Writer
	ret driver.Fingerprint

	headerFraming bool
}

const v1FetchPrefix = `v1Fetch.`

func (r *rpcv1Fetch) Bind(ctx context.Context, conn *jsonrpc2.Connection) (jsonrpc2.ConnectionOptions, error) {
	rc := rpcv1FetchConn{
		rpcv1Fetch: r,
		ready:      make(chan struct{}),
		conn:       conn,
	}
	f := jsonrpc2.RawFramer()
	if r.headerFraming {
		f = jsonrpc2.HeaderFramer()
	}
	return jsonrpc2.ConnectionOptions{
		Framer:    f,
		Preempter: &rc,
		Handler:   &rc,
	}, nil
}

type rpcv1FetchConn struct {
	*rpcv1Fetch
	ready     chan struct{}
	readyOnce sync.Once
	conn      *jsonrpc2.Connection
}

func (r *rpcv1FetchConn) Handle(ctx context.Context, req *jsonrpc2.Request) (interface{}, error) {
	if req.Method == v1FetchPrefix+`Init` {
		defer r.readyOnce.Do(func() { close(r.ready) })
	} else {
		<-r.ready
	}
	switch req.Method {
	case v1FetchPrefix + `Init`:
		res := FetchInitResponse{
			Root: r.root,
		}
		if r.prev != "" {
			res.Fingerprint = []byte(r.prev)
		}
		return &res, nil
	case v1FetchPrefix + `SetFingerprint`:
		var p SetFingerprintParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, jsonrpc2.ErrInvalidParams
		}
		r.ret = driver.Fingerprint(p.Fingerprint)
	case v1FetchPrefix + `FetchURL`:
		var p FetchParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, jsonrpc2.ErrInvalidParams
		}
		go r.fetch(req.ID, &p)
		return nil, jsonrpc2.ErrAsyncResponse
	case v1FetchPrefix + `AddFile`:
		var p AddParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, jsonrpc2.ErrInvalidParams
		}
		go r.copyFile(req.ID, &p)
		return nil, jsonrpc2.ErrAsyncResponse
	default:
		return nil, jsonrpc2.ErrMethodNotFound
	}
	return nil, nil
}

func (r *rpcv1FetchConn) Preempt(ctx context.Context, req *jsonrpc2.Request) (interface{}, error) {
	if req.IsCall() {
		return nil, jsonrpc2.ErrNotHandled
	}
	switch req.Method {
	case v1FetchPrefix + `Cancel`:
		var id jsonrpc2.ID
		if err := json.Unmarshal(req.Params, &id); err != nil {
			return nil, err
		}
		r.conn.Cancel(id)
	default:
		return nil, jsonrpc2.ErrMethodNotFound
	}
	return nil, nil
}

type (
	FetchInitResponse struct {
		Root         string          `json:"root"`
		Fingerprint  json.RawMessage `json:"fingerprint"`
		Capabilities []string        `json:"capabilities"`
	}
	SetFingerprintParams struct {
		Fingerprint json.RawMessage `json:"fingerprint"`
	}
	FetchParams struct {
		Headers http.Header `json:"headers"`
		URL     string      `json:"url"`
		Method  string      `json:"method"`
	}
	FetchResponse struct {
		Headers http.Header `json:"headers"`
		Body    string      `json:"body"`
		Code    int         `json:"code"`
	}
	AddParams struct {
		File string `json:"file"`
	}
)

func (r *rpcv1FetchConn) fetch(id jsonrpc2.ID, p *FetchParams) {
	var res FetchResponse
	var err error
	defer func() {
		var rerr error
		if err != nil {
			rerr = r.conn.Respond(id, nil, err)
		} else {
			rerr = r.conn.Respond(id, &res, nil)
		}
		if rerr != nil {
			zlog.Warn(r.async).Err(rerr).Msg("error sending fetch response")
		}
	}()
	// make http request
	var req *http.Request
	req, err = http.NewRequestWithContext(r.async, p.Method, p.URL, nil)
	if err != nil {
		return
	}
	var resp *http.Response
	resp, err = r.c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.ContentLength != 0 {
		var f *os.File
		f, err = os.CreateTemp(r.root, "fetch.*")
		if err != nil {
			return
		}
		defer f.Close()
		if _, cp := io.Copy(f, resp.Body); cp != nil {
			err = cp
			return
		}
		res.Body = f.Name()
	}
	res.Headers = resp.Header
	res.Code = resp.StatusCode
}

func (r *rpcv1FetchConn) copyFile(id jsonrpc2.ID, p *AddParams) {
	var err error
	defer func() {
		var rerr error
		if err != nil {
			rerr = r.conn.Respond(id, nil, err)
		} else {
			rerr = r.conn.Respond(id, struct{}{}, nil)
		}
		if rerr != nil {
			zlog.Warn(r.async).Err(rerr).Msg("error sending fetch response")
		}
	}()
	var src *os.File
	src, err = os.Open(filepath.Join(r.root, p.File))
	if err != nil {
		return
	}
	defer src.Close()
	wp := path.Clean(p.File)
	r.mu.Lock()
	defer r.mu.Unlock()
	var dst io.Writer
	dst, err = r.w.Create(wp)
	if err != nil {
		return
	}
	defer r.w.Flush()
	_, err = io.Copy(dst, src)
}
