package httputil

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRangeReaderAt(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefghijklmnop"), 32*1024) // 512 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "blob", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)

	ra := NewRangeReaderAt(srv.Client(), srv.URL, nil, int64(len(data)))

	// Read across a chunk boundary to exercise read-ahead.
	p := make([]byte, 300*1024)
	n, err := ra.ReadAt(p, 100*1024)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(p) {
		t.Fatalf("got %d bytes, want %d", n, len(p))
	}
	if !bytes.Equal(p, data[100*1024:100*1024+len(p)]) {
		t.Fatal("data mismatch")
	}

	// EOF at end.
	_, err = ra.ReadAt(make([]byte, 1), int64(len(data)))
	if err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
}

func TestRangeReaderAtBufferHit(t *testing.T) {
	var requests int
	data := bytes.Repeat([]byte{0x42}, readAheadSize*2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.ServeContent(w, r, "blob", time.Now(), bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)

	ra := NewRangeReaderAt(srv.Client(), srv.URL, nil, int64(len(data)))

	buf := make([]byte, 512)
	if _, err := ra.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	before := requests
	if _, err := ra.ReadAt(buf, 256); err != nil {
		t.Fatal(err)
	}
	if requests != before {
		t.Fatalf("second read triggered HTTP request: %d -> %d", before, requests)
	}
}

func TestParseContentRangeTotal(t *testing.T) {
	t.Parallel()
	got, err := ParseContentRangeTotal("bytes 0-15/12345")
	if err != nil {
		t.Fatal(err)
	}
	if got != 12345 {
		t.Fatalf("got %d, want 12345", got)
	}
}
