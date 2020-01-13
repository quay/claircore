package fastesturl

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"github.com/rs/zerolog"
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
	}
}

// Do will return the first *http.Response which passes
// f.RespCheck.
//
// If no successful *http.Response is obtained a nil is returned.
// Any ctx timeout or cancelation must be provided by the caller.
func (f *FastestURL) Do(ctx context.Context) *http.Response {
	log := zerolog.Ctx(ctx).With().Str("routine", "fasesturl_do").Logger()
	cond := sync.NewCond(&sync.Mutex{})
	var response *http.Response
	// immediately lock so workers do not write to response
	// before Do method blocks on cond.Wait()
	cond.L.Lock()
	for _, url := range f.URLs {
		u := url
		go func() {
			defer cond.Signal()
			req := f.Request.Clone(ctx)
			req.URL = u
			req.Host = u.Host
			resp, err := f.Client.Do(req)
			if err != nil {
				log.Error().Err(err).Str("url", url.String()).Msg("failed to make request for url")
				return
			}
			// early return if resp doesnt pass check
			if !f.RespCheck(resp) {
				resp.Body.Close()
				return
			}
			// respCheck passed, lock access to response var
			cond.L.Lock()
			if response == nil {
				response = resp
			} else {
				// another routine has set response, close this body and discard
				resp.Body.Close()
			}
			cond.L.Unlock()
		}()
	}
	// wait on go routines to signal. when a signal occurs
	// check if a worker set response and if so return it.
	// break loop when all workers have signal
	for lim, i := len(f.URLs), 0; i < lim; i++ {
		cond.Wait()
		if response != nil {
			cond.L.Unlock()
			return response
		}
	}
	// exhausted all workers without response populated.
	// cond.L.Lock() will be locked from latest cond.Wait() signal
	// unlock it and return nil
	cond.L.Unlock()
	return nil
}
