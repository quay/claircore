package fastesturl

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ReqCheckFunc checks if a *http.Response
// is valid for returning to a client
type RespCheck func(*http.Response) bool

// FatestURL implements a method for obtaining the first
// *http.Response object returned from a list of URLs.
type FastestURL struct {
	// an http client to use for all requests
	Client *http.Client
	// a list of urls we will concurrecntly attempt to request
	URLs []*url.URL
	// a template request object we will copy fields from
	Request *http.Request
	// a function provided by the caller to determine if a request
	// should be returned
	RespCheck RespCheck
	// protects Response
	mu *sync.Mutex
	// the fastest http Response which passed ReqCheckFunc
	Response *http.Response
}

// New is a constructor for a FastestURL
func New(client *http.Client, req *http.Request, check RespCheck, urls []*url.URL) *FastestURL {
	if client == nil {
		client = &http.Client{}
	}
	if req == nil {
		req = &http.Request{}
	}
	if check == nil {
		check = func(resp *http.Response) bool {
			if resp.StatusCode == 200 {
				return true
			}
			return false
		}
	}
	return &FastestURL{
		Client:    client,
		URLs:      urls,
		Request:   req,
		RespCheck: check,
		mu:        &sync.Mutex{},
	}
}

// Do will return the first *http.Response which passes
// f.RespCheck.
//
// If no successful *http.Response is obtained a nil is returned
func (f *FastestURL) Do(ctx context.Context) *http.Response {
	cond := sync.NewCond(f.mu)
	// immediately lock so workers do not write to f.Response
	// before Do method blocks on cond.Wait()
	cond.L.Lock()
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, url := range f.URLs {
		u := url
		go func() {
			defer cond.Broadcast()
			req := f.Request.Clone(tctx)
			req.URL = u
			req.Host = u.Host
			resp, err := f.Client.Do(req)
			if err != nil {
				return
			}
			if f.RespCheck(resp) {
				f.mu.Lock()
				if f.Response == nil {
					f.Response = resp
				} else {
					// another routine has set f.Response, close this body and discard
					resp.Body.Close()
				}
				f.mu.Unlock()
			}
		}()
	}
	// wait on go routines to broadcast. when a broadcast occurs
	// check if a worker set f.Response and if so return it.
	// break loop when all workers have broadcasted
	for lim, i := len(f.URLs), 0; i < lim; i++ {
		cond.Wait()
		if f.Response != nil {
			cond.L.Unlock()
			return f.Response
		}
	}
	// exhausted all workers without f.Response populated.
	// cond.L.Lock() will be locked from latest cond.Wait() broadcast
	// unlock it and return nil
	cond.L.Unlock()
	return nil
}
