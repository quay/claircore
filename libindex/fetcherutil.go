package libindex

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// NewRequest is akin to [http.NewRequestWithContext], but avoids URL
// re-parsing and always makes a GET request.
func newRequest(ctx context.Context, u *url.URL, header http.Header) *http.Request {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       nil,
		Host:       u.Host,
	}
	if header != nil {
		req.Header = header.Clone()
	} else {
		req.Header = make(http.Header)
	}
	return req.WithContext(ctx)
}

// GzipDecompressedSize makes a request to the same URL as "resp", attempting to
// interpret the end of the resource as a gzip footer.
//
// This will report -1 if the size can't be determined or seems obviously wrong.
func gzipDecompressedSize(ctx context.Context, log *slog.Logger, c *http.Client, resp *http.Response) int64 {
	// Build a request to the resource, requesting the last 4 bytes.
	log = log.With("url", resp.Request.URL)
	req := newRequest(ctx, resp.Request.URL, resp.Request.Header)
	req.Header.Set(`Range`, `bytes=-4`)

	// Send+read the request.
	res, err := c.Do(req)
	if err != nil {
		log.WarnContext(ctx, "unable to re-request url", "reason", err)
		return -1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPartialContent {
		log.DebugContext(ctx, "unexpected HTTP status (not 206)", "status", res.Status)
		return -1
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(res.Body, b); err != nil {
		log.WarnContext(ctx, "unable to read resource", "reason", err)
		return -1
	}
	sz := int64(binary.BigEndian.Uint32(b))
	// Try to get the resource's size:
	var rSz int64
	if _, after, ok := strings.Cut(res.Header.Get(`content-range`), "/"); ok && after != "*" {
		rSz, _ = strconv.ParseInt(after, 10, 64)
	}

	// Assume that the compressed file was actually compressible and didn't end
	// up larger.
	//
	// The reported size is modulo 2³², so there's not a good way to know if
	// this is a very large file or a very small one. If it were possible to
	// tell if this were one gzip file, it would be possible to guess based on
	// the reported length if the size has wrapped.
	//
	// If there are multiple concatenated gzip files, the reported length of
	// the last one makes sense but is useless.
	if sz < rSz {
		return -1
	}
	return sz
}
