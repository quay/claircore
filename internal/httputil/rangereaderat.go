package httputil

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// ponytail: read-ahead is a single global buffer per RangeReaderAt; concurrent
// ReadAt calls serialize on mu. Upgrade path: per-chunk cache keyed by offset.
const readAheadSize = 256 * 1024

// RangeReaderAt is an io.ReaderAt backed by HTTP range requests.
type RangeReaderAt struct {
	client  *http.Client
	url     string
	headers http.Header
	size    int64

	mu     sync.Mutex
	buf    []byte
	bufOff int64
}

// NewRangeReaderAt returns a RangeReaderAt for the blob at url with the given
// size.
//
// headers are copied into each request. size must be the total blob size in
// bytes.
func NewRangeReaderAt(client *http.Client, url string, headers http.Header, size int64) *RangeReaderAt {
	h := headers.Clone()
	if h == nil {
		h = make(http.Header)
	}
	return &RangeReaderAt{
		client:  client,
		url:     url,
		headers: h,
		size:    size,
	}
}

// Size reports the total blob size.
func (r *RangeReaderAt) Size() int64 { return r.size }

// ReadAt implements io.ReaderAt.
func (r *RangeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("httputil: ReadAt: negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	start := off
	wantLen := len(p)
	total := r.readFromBuffer(p, off)
	if total == wantLen {
		return total, nil
	}
	if total > 0 {
		p = p[total:]
		off += int64(total)
	}

	fetch := int64(len(p))
	if fetch < readAheadSize {
		fetch = readAheadSize
	}
	if off+fetch > r.size {
		fetch = r.size - off
	}

	data, err := r.fetch(off, fetch)
	if err != nil {
		if total > 0 {
			return total, err
		}
		return 0, err
	}
	r.bufOff = off
	r.buf = data

	total += copy(p, r.buf)
	if total < wantLen && start+int64(total) >= r.size {
		return total, io.EOF
	}
	return total, nil
}

func (r *RangeReaderAt) readFromBuffer(p []byte, off int64) int {
	if len(r.buf) == 0 {
		return 0
	}
	end := r.bufOff + int64(len(r.buf))
	if off < r.bufOff || off >= end {
		return 0
	}
	return copy(p, r.buf[off-r.bufOff:])
}

func (r *RangeReaderAt) fetch(off, n int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = r.headers.Clone()
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+n-1))

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent:
		return io.ReadAll(resp.Body)
	case http.StatusOK:
		// ponytail: inconsistent server ignored Range; skip to offset in body.
		if _, err := io.CopyN(io.Discard, resp.Body, off); err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(resp.Body, n))
	}
	return nil, CheckResponse(resp, http.StatusPartialContent, http.StatusOK)
}

// ParseContentRangeTotal extracts the total size from a Content-Range header.
//
// For example, "bytes 0-15/12345" returns 12345.
func ParseContentRangeTotal(h string) (int64, error) {
	if !strings.HasPrefix(h, "bytes ") {
		return 0, fmt.Errorf("httputil: invalid Content-Range: %q", h)
	}
	_, totalText, ok := strings.Cut(h, "/")
	if !ok {
		return 0, fmt.Errorf("httputil: invalid Content-Range: %q", h)
	}
	total, err := strconv.ParseInt(totalText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("httputil: invalid Content-Range total: %w", err)
	}
	return total, nil
}
