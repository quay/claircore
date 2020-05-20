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
		client = http.DefaultClient
	}
	if req == nil {
		req = &http.Request{}
	}
	if check == nil {
		check = func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
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
// Any timeout or cancellation must be provided by the caller.
func (f *FastestURL) Do(ctx context.Context) *http.Response {
	log := zerolog.Ctx(ctx).With().Str("routine", "fasesturl_do").Logger()
	var wg sync.WaitGroup
	result := make(chan *http.Response)
	wg.Add(len(f.URLs))
	ctx, done := context.WithCancel(ctx)
	defer done()

	go func() {
		wg.Wait()
		close(result)
	}()
	for _, url := range f.URLs {
		u := url
		go func() {
			defer wg.Done()
			req := f.Request.Clone(ctx)
			req.URL = u
			req.Host = u.Host
			resp, err := f.Client.Do(req)
			// Can't defer the body.Close(), because we can only close it if we're not
			// going to return it.
			if err != nil {
				log.Error().Err(err).Str("url", u.String()).Msg("failed to make request for url")
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			if !f.RespCheck(resp) {
				resp.Body.Close()
				return
			}
			select {
			case result <- resp:
				done()
			case <-ctx.Done():
				resp.Body.Close()
			}
		}()
	}
	return <-result
}
