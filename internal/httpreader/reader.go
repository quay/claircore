package httpreader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// Reader implements [io.ReaderAt] over an HTTP resource that implements range requests.
//
// The Reader is guaranteed to only makes GET requests.
//
// Callers can use an [io.SectionReader] if they require an [io.Reader] interface.
type Reader struct {
	ctx     context.Context // This is OK, I swear.
	c       *http.Client
	done    context.CancelFunc
	res     string
	headers http.Header

	validator string
	modTime   time.Time
	size      int64 // Discovered size of the resource "res."
	guessed   bool  // Did the rangefind method guess at the size?
}

// New constructs a reader for the resource at "uri", using the supplied [context.Context] and [http.Client].
//
// The Context is used for the lifetime of the Reader.
// All ReadAt calls translate to network roundtrips.
// Callers should arrange for buffering and chunking for the best performance.
// They may also want to check the discovered size and eagerly fetch the resource if it's under some threshold.
// This is not handled in this package.
//
// The returned Reader must have [Reader.Close] called or the program may panic.
func New(ctx context.Context, c *http.Client, uri string, opts ...Option) (*Reader, error) {
	ctx, done := context.WithCancel(ctx)
	ok := false
	defer func() {
		if !ok {
			done()
		}
	}()
	r := Reader{
		ctx:  ctx,
		done: done,
		c:    c,
		res:  uri,
		size: -1,
	}
	for _, opt := range opts {
		if err := opt(ctx, &r); err != nil {
			return nil, err
		}
	}
	if err := r.rangefind(); err != nil {
		return nil, err
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&r, func(r *Reader) {
		panic(fmt.Sprintf("%s:%d: httpreader.Reader not closed", file, line))
	})
	ok = true
	return &r, nil
}

// Close implements [io.Closer].
//
// Callers must call Close on any Reader to release resources, or the program may panic.
func (r *Reader) Close() error {
	runtime.SetFinalizer(r, nil)
	r.done()
	return nil
}

var (
	_ io.ReaderAt = (*Reader)(nil)
	_ io.Closer   = (*Reader)(nil)
)

// ReadAt implements [io.ReaderAt].
func (r *Reader) ReadAt(b []byte, off int64) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.res, nil)
	if err != nil {
		return 0, err
	}
	r.setRange(req, off, int64(len(b)))
	res, err := r.c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusPartialContent: // OK
	case http.StatusOK:
		if off != 0 {
			return 0, fmt.Errorf("httpreader: server botch: %d (range: %s)", res.StatusCode, req.Header.Get(`range`))
		}
	case http.StatusRequestedRangeNotSatisfiable:
		return 0, fmt.Errorf("httpreader: server botch: %d (range: %s)", res.StatusCode, req.Header.Get(`range`))
	default:
		return 0, fmt.Errorf("httpreader: unexpected status: %d", res.StatusCode)
	}
	n, err := io.ReadFull(res.Body, b)
	atEOF := off+int64(n) == r.size
	switch {
	case errors.Is(err, io.EOF):
		err = io.ErrNoProgress
	case atEOF:
		err = io.EOF
	}

	return n, err
}

// SetRange sets the Range header for "sz" bytes starting at "off".
func (r *Reader) setRange(req *http.Request, off int64, sz int64) {
	switch {
	case r.validator != "":
		req.Header.Set(`If-Match`, r.validator)
	case !r.modTime.IsZero():
		req.Header.Set(`If-Unmodified-Since`, r.modTime.Format(http.TimeFormat))
	}
	// Throw in a branch to make this function useful in the search function.
	var last int64
	if r.size < 0 {
		last = off + sz
	} else {
		last = min(off+sz, r.size)
	}
	last--
	req.Header.Set(`Range`, fmt.Sprintf(`bytes=%d-%d`, off, last))
	for n, vs := range r.headers {
		for _, v := range vs {
			req.Header.Add(n, v)
		}
	}
}

// Rangefind attempts to discover the size, range support, and version information for the remote resource.
func (r *Reader) rangefind() error {
	// If the Option was provided, we're done.
	if r.size != -1 {
		return nil
	}
	// First, issue an extremely weird range request: request the last byte of a resource without issuing a HEAD to check if the server supports it.
	// The returned request then has some caveats, explained below.
	// The GET-only flow is done to be compatible with some signed URLs and to prevent middleware boxes from lying when seeing the HEAD request.
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.res, nil)
	if err != nil {
		return err
	}

	req.Header.Add(`range`, `bytes=-1`)
	for n, vs := range r.headers {
		for _, v := range vs {
			req.Header.Add(n, v)
		}
	}
	res, err := r.c.Do(req)
	if err != nil {
		return err
	}
	if err := res.Body.Close(); err != nil {
		return err
	}
	// RFC7232 handling, so we error out if the resource changes.
	// This _really_ shouldn't happen with something content-addressed like container storage, but better safe than sorry.
	//
	// A server that interprets each range as a unique resource for the purpose of generating a validator would break this.
	// I think that's not strictly RFC-compliant, though.
	r.validator = res.Header.Get(`etag`)
	if strings.HasPrefix(r.validator, `W/`) {
		// Ignore weak discriminators. Can't use these, per RFC.
		r.validator = ""
	}
	r.modTime, err = time.Parse(http.TimeFormat, res.Header.Get(`last-modified`))
	if err != nil {
		// Use the reported time, unless that was absent or malformed; in that case just use "now".
		r.modTime = time.Now().UTC()
	}

	switch res.StatusCode {
	case http.StatusPartialContent:
	case http.StatusRequestedRangeNotSatisfiable:
	case http.StatusOK:
		// All the above are OK
	default:
		return fmt.Errorf("httpreader: unexpected response status: %s", res.Status)
	}

	// Now, for a bunch of RFC7233 tricks:
	// Does the server advertise support?
	var rangeOK bool
Ranges:
	for _, t := range res.Header["Accept-Ranges"] {
		switch t {
		case "bytes":
			rangeOK = true
			fallthrough
		case "none":
			break Ranges
		}
	}
	// Is the Content-Range populated correctly?
	if cr := res.Header.Get(`content-range`); cr != "" {
		var rg ContentRange
		if err := rg.Parse(cr); err == nil {
			switch {
			case rg.Length != -1:
				r.size = rg.Length
			case rg.Length == -1 && rg.Last != -1:
				r.size = rg.Last + 1
			}
		}
	}
	// If the server just responded with 200 OK _because_ of the negative range request but otherwise supports ranges, this captures the size:
	if res.StatusCode == http.StatusOK {
		r.size = res.ContentLength
	}
	rangeOK = rangeOK || res.StatusCode == http.StatusPartialContent && r.size != -1

	switch {
	case !rangeOK && r.size == -1:
		// Can't issue range requests and couldn't find the size.
		fallthrough
	case !rangeOK && r.size != -1:
		// Can't issue range requests and found the size.
		return rangeUnsupported(r.res)
	case rangeOK && r.size == -1:
		// Can issue range requests and couldn't find the size.
		//
		// As a last-ditch effort, search for it.
		if err := r.searchSize(); err != nil {
			return err
		}
	case rangeOK && r.size != -1:
		// Can issue range requests and found the size.
	}

	return nil
}

// RangeUnsupported returns an informative error that is [errors.Is]-wise equal
// to [errors.ErrUnsupported].
func rangeUnsupported(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		panic(fmt.Sprintf("programmer error: bogus URL: %v", err))
	}
	return &errRangeUnsupported{u: u}
}

var _ error = (*errRangeUnsupported)(nil)

type errRangeUnsupported struct{ u *url.URL }

func (e *errRangeUnsupported) Error() string {
	return fmt.Sprintf("httpreader: origin %q does not support range requests (resource: %q)", e.u.Host, e.u.Path)
}

func (e *errRangeUnsupported) Is(tgt error) bool {
	return tgt == errors.ErrUnsupported
}

// SearchSize handles a server that advertises range support but refuses to specify the length.
//
// This method brute forces the length by finding bounds where the lower is satisfiable and upper is not,
// then performing range requests between them to find the last byte returned.
// This algorithm is transfer- and latency-inefficient and any server that forces us to resort to this should be ashamed.
func (r *Reader) searchSize() error {
	// No idea how this could happen -- the Content-Range handling should have deduced a size even if the server refuses to put the total length in the header.
	//
	// Best I can tell this closer in complexity to an "exponential search" than a "binary search".
	// The algorithm implemented is (I think) novel because it's looking for nonexistence instead of a known index or value.
	// That means the complexity (meaning number of requests) here should be something like O(log(n)+m).
	// The window grows with the requests because the power of logarithms means we really want to get to that quickly.
	const window = (1 << 20) * 250 // 250 MiB
	var lower, upper int64 = 0, window
	proto, err := http.NewRequest(http.MethodGet, r.res, nil)
	if err != nil {
		return err
	}
	u, _ := url.Parse(r.res)
	reqs := 1
	success := false
	defer recordSearchCount(r.ctx, u.Host, &reqs, &success)
	// Rangefind an initial window.
	var rg ContentRange
Rangefind:
	for ; ; reqs++ {
		req := proto.Clone(r.ctx)
		r.setRange(req, upper-1, 3)
		res, err := r.c.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()

		switch res.StatusCode {
		case http.StatusPartialContent:
		case http.StatusRequestedRangeNotSatisfiable:
			// These are some bounds, good to search.
			break Rangefind
		default: // ???
			return fmt.Errorf("httpreader: unexpected status while searching for end: %s", res.Status)
		}

		// Check if the Content-Range is populated with a size for some reason, now:
		cr := res.Header.Get(`content-range`)
		// This shouldn't happen, but we're doing weird access patterns so just belt and suspenders (bracers):
		if cr == "" {
			return fmt.Errorf("httpreader: origin %q has an odd reading of RFC7233", u.Host)
		}
		if err := rg.Parse(cr); err != nil {
			return fmt.Errorf("httpreader: origin %q header botch: %w", u.Host, err)
		}
		if rg.Length != -1 {
			// Should never be 0: layers can't be 0-sized.
			// This assumes 0 _could_ happen just in case it's used in another context.
			//
			// So, we just needed to make any forwards-range request to get the server to tell us the length.
			r.size = rg.Length
			success = true
			return nil
		}
		// Check if we manged to request the actual end:
		if (rg.Last+1)-rg.First < 3 {
			r.size = rg.Last + 1
			success = true
			return nil
		}
		lower = upper
		upper += upper
	}

	// Now, search using our bounds.
	// This requests "searchWin" sized ranges and examines the response to see how much was returned.
	//
	// - If nothing is returned, the upper bound is dropped.
	// - If the whole range is returned, the lower bound is raised.
	// - If part of the range is returned, we've found the end.
	//
	// A bigger window means fewer requests, but more transfer.
	// The worst case for requests should be something like:
	//
	//	log(window/searchWin) = log(((1<<20)*250)/1024) ≅ 5.4 = 6
	//
	// The searchWin value would need to be 3072 (3 KiB) to get the worst case requests under 5.
	// Given that TCP receive buffers should be well north of that on machines, that's
	//
	//	(3072*5) - (1024*6) = 9216
	//
	// extra bytes of transfer every time this function hits worst-case behavior, at best.
	// The above napkin math doesn't bother with protocol overhead.
	// Alternatively, the window size could be shrunk, but that means more rangefinding requests in the loop above.
	// Shrinking the window size to 100 MiB still results in a worst-case 5.3 requests here.
	// Seeing as one additional rangefinding request negates any advantage, the current magic numbers seem OK.
	const searchWin = 1024
	lowerBucket, upperBucket := lower/searchWin, upper/searchWin
	nBuckets := upperBucket - lowerBucket
	if (upper-lower)%searchWin != 0 {
		nBuckets++
	}
	ceil := int(math.Ceil(math.Log(float64(nBuckets))))
	attrs := []slog.Attr{
		slog.Int("big_O", reqs+ceil),
		slog.Int("bucket_size", searchWin),
		slog.Int64("buckets", nBuckets),
		slog.GroupAttrs(
			"range",
			slog.Int64("lower", lower),
			slog.Int64("upper", upper),
		),
	}
	var pivots []int64
	lim := reqs + (2 * ceil)
	for reqs++; reqs <= lim; reqs++ {
		pivot := ((upper - lower) / 2)
		pivot += lower
		pivots = append(pivots, pivot)
		req := proto.Clone(r.ctx)
		r.setRange(req, pivot, searchWin)
		res, err := r.c.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		switch res.StatusCode {
		case http.StatusPartialContent:
		case http.StatusRequestedRangeNotSatisfiable:
			upper = pivot
			continue
		default: // ???
			return fmt.Errorf("httpreader: unexpected status: %s", res.Status)
		}
		cr := res.Header.Get(`content-range`)
		if cr == "" {
			return fmt.Errorf("httpreader: origin %q has an odd reading of RFC7233", u.Host)
		}
		if err := rg.Parse(cr); err != nil {
			return fmt.Errorf("httpreader: origin %q header botch: %w", u.Host, err)
		}
		// Check if we manged to request the actual end:
		if (rg.Last+1)-rg.First < searchWin {
			r.size = rg.Last + 1
			break
		}
		lower = pivot
	}
	if reqs > lim {
		return errors.New("loop")
	}
	slog.LogAttrs(r.ctx, slog.LevelDebug, "size search done", append(
		attrs,
		slog.Int("requests", reqs),
		slog.Any("pivots", pivots),
	)...)

	success = true
	return nil
}

// Size reports the discovered size of the HTTP resource.
//
// This function may report a guessed size less than zero.
// This means the Reader will issue range requests, but will allow arbitrary offsets.
// Callers should expect something like [io.Reader] semantics in that case.
func (r *Reader) Size() int64 { return r.size }
