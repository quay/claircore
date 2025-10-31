package vex

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"

	"github.com/quay/claircore/internal/httputil"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	deletedTemplate = `{"document":{"tracking":{"id":"%s","status":"deleted"}}}`
	cvePathRegex    = regexp.MustCompile(`^\d{4}/(cve-\d{4}-\d{4,}).json$`)
)

// Fetch pulls data down from the Red Hat VEX endpoints. The order of operations is:
//  1. Check if we need to process the entire archive of data. If yes:
//     - Make a request to discover the latest archive endpoint.
//     - Make a HEAD request to archive endpoint to get the last-modified header.
//     - Save the last-modified time in the fingerprint's requestTime.
//  2. Process the changes.csv file, requesting and appending the entries that changed since the fingerprint's requestTime.
//  3. Process the deletions.csv file, processing the entries that changed since the fingerprint's requestTime.
//  4. If we need to process entire archive, request the archive data and append the entries that have not been changed or deleted.
//
// This helps to ensure that we only persist one copy of an advisory in the worst possible case. In most cases,
// after the initial load, the number of processed files should be very small.
func (u *Updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	fp, err := parseFingerprint(hint)
	if err != nil {
		return nil, hint, err
	}

	f, err := tmp.NewFile("", "rhel-vex.")
	if err != nil {
		return nil, hint, err
	}

	cw := snappy.NewBufferedWriter(f)

	var success bool
	defer func() {
		if err := cw.Close(); err != nil {
			slog.WarnContext(ctx, "unable to close snappy writer", "reason", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			slog.WarnContext(ctx, "unable to seek file back to start", "reason", err)
		}
		if !success {
			if err := f.Close(); err != nil {
				slog.WarnContext(ctx, "unable to close spool", "reason", err)
			}
		}
	}()

	var compressedURL *url.URL
	// Is this the first run or has the updater changed since the last run?
	processArchive := fp.changesEtag == "" || fp.version != updaterVersion
	if processArchive {
		// We need to go after the full corpus of vulnerabilities
		// First we target the archive_latest.txt file.
		var err error
		compressedURL, err = u.getCompressedFileURL(ctx)
		if err != nil {
			return nil, hint, fmt.Errorf("could not get compressed file URL: %w", err)
		}
		slog.DebugContext(ctx, "got compressed URL", "url", compressedURL)

		fp.requestTime, err = u.getLastModified(ctx, compressedURL)
		if err != nil {
			return nil, hint, fmt.Errorf("could not get last-modified header: %w", err)
		}
	}

	changed := map[string]bool{}
	err = u.processChanges(ctx, cw, fp, changed)
	if err != nil {
		return nil, hint, err
	}

	err = u.processDeletions(ctx, cw, fp, changed)
	if err != nil {
		return nil, hint, err
	}

	if processArchive {
		rctx, cancel := context.WithTimeout(ctx, u.compressedFileTimeout)
		defer cancel()

		if compressedURL == nil {
			return nil, hint, fmt.Errorf("compressed file URL needs to be populated")
		}
		req, err := http.NewRequestWithContext(rctx, http.MethodGet, compressedURL.String(), nil)
		if err != nil {
			return nil, hint, err
		}

		res, err := u.client.Do(req)
		if err != nil {
			return nil, hint, err
		}
		defer res.Body.Close()

		err = httputil.CheckResponse(res, http.StatusOK)
		if err != nil {
			return nil, hint, fmt.Errorf("unexpected response from latest compressed file: %w", err)
		}

		z, err := zreader.Reader(res.Body)
		if err != nil {
			return nil, hint, err
		}
		defer z.Close()
		r := tar.NewReader(z)

		var (
			h              *tar.Header
			buf, bc        bytes.Buffer
			entriesWritten int
		)
		for h, err = r.Next(); errors.Is(err, nil); h, err = r.Next() {
			buf.Reset()
			bc.Reset()
			if h.Typeflag != tar.TypeReg {
				continue
			}
			year, err := strconv.ParseInt(path.Dir(h.Name), 10, 64)
			if err != nil {
				return nil, hint, fmt.Errorf("error parsing year %w", err)
			}
			if year < lookBackToYear {
				continue
			}
			if changed[path.Base(h.Name)] {
				// We've already processed this file don't bother appending it to the output
				continue
			}
			buf.Grow(int(h.Size))
			if _, err := buf.ReadFrom(r); err != nil {
				return nil, hint, err
			}
			// Here we construct new-line-delimited JSON by first compacting the
			// JSON from the file and writing it to the bc buf, then writing a newline,
			// and finally writing all those bytes to the snappy.Writer.
			err = json.Compact(&bc, buf.Bytes())
			if err != nil {
				return nil, hint, fmt.Errorf("error compressing JSON %s: %w", h.Name, err)
			}
			bc.WriteByte('\n')
			if _, err := io.Copy(cw, &bc); err != nil {
				return nil, hint, fmt.Errorf("error writing compacted JSON to tmp file: %w", err)
			}
			entriesWritten++
		}
		if !errors.Is(err, io.EOF) {
			return nil, hint, fmt.Errorf("error reading tar contents: %w", err)
		}

		slog.DebugContext(ctx, "finished writing compressed data to spool",
			"updater", u.Name(),
			"entries written", entriesWritten)
	}

	fp.version = updaterVersion
	fp.requestTime = time.Now()
	success = true
	return f, driver.Fingerprint(fp.String()), nil
}

func (u *Updater) getCompressedFileURL(ctx context.Context) (*url.URL, error) {
	latestURI, err := u.url.Parse(latestFile)
	if err != nil {
		return nil, err
	}
	latestReq, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURI.String(), nil)
	if err != nil {
		return nil, err
	}
	latestRes, err := u.client.Do(latestReq)
	if err != nil {
		return nil, err
	}
	defer latestRes.Body.Close()

	err = httputil.CheckResponse(latestRes, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("unexpected response from archive_latest.txt: %w", err)
	}

	body, err := io.ReadAll(latestRes.Body) // Fine to use as expecting small number of bytes.
	if err != nil {
		return nil, err
	}

	compressedFilename := string(body)
	compressedURL, err := u.url.Parse(compressedFilename)
	if err != nil {
		return nil, err
	}
	return compressedURL, nil
}

func (u *Updater) getLastModified(ctx context.Context, cu *url.URL) (time.Time, error) {
	var empty time.Time
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cu.String(), nil)
	if err != nil {
		return empty, err
	}

	res, err := u.client.Do(req)
	if err != nil {
		return empty, err
	}
	defer res.Body.Close()

	err = httputil.CheckResponse(res, http.StatusOK)
	if err != nil {
		return empty, fmt.Errorf("unexpected HEAD response from latest compressed file: %w", err)
	}

	lm := res.Header.Get("last-modified")
	return time.Parse(http.TimeFormat, lm)
}

// ProcessChanges deals with the published changes.csv, adding records
// to w means they are deemed to have changed since the compressed
// file was last processed. w and fp can be modified.
func (u *Updater) processChanges(ctx context.Context, w io.Writer, fp *fingerprint, changed map[string]bool) error {
	tf, err := tmp.NewFile("", "rhel-vex-changes.")
	if err != nil {
		return err
	}
	defer tf.Close()

	uri, err := u.url.Parse(changesFile)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return err
	}
	if fp.changesEtag != "" {
		req.Header.Add("If-None-Match", fp.changesEtag)
	}
	res, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if t := fp.changesEtag; t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("unexpected response from changes.csv: %s", res.Status)
	}
	fp.changesEtag = res.Header.Get("etag")

	var r io.Reader = res.Body
	if _, err := io.Copy(tf, r); err != nil {
		return fmt.Errorf("unable to copy resp body to tempfile: %w", err)
	}
	if n, err := tf.Seek(0, io.SeekStart); err != nil || n != 0 {
		return fmt.Errorf("unable to seek changes to start: at %d, %v", n, err)
	}

	rd := csv.NewReader(tf)
	rd.FieldsPerRecord = 2
	rd.ReuseRecord = true
	var (
		l       int
		buf, bc bytes.Buffer
	)
	rec, err := rd.Read()
	for ; err == nil; rec, err = rd.Read() {
		buf.Reset()
		bc.Reset()
		if len(rec) != 2 {
			return fmt.Errorf("could not parse changes.csv file")
		}

		cvePath, uTime := rec[0], rec[1]
		year, err := strconv.ParseInt(path.Dir(cvePath), 10, 64)
		if err != nil {
			return fmt.Errorf("error parsing year %w", err)
		}
		if year < lookBackToYear {
			continue
		}
		updatedTime, err := time.Parse(time.RFC3339, uTime)
		if err != nil {
			return fmt.Errorf("line %d: %w", l, err)
		}
		if updatedTime.Before(fp.requestTime) {
			continue
		}

		changed[path.Base(cvePath)] = true

		advisoryURI, err := u.url.Parse(cvePath)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, advisoryURI.String(), nil)
		if err != nil {
			return fmt.Errorf("error creating advisory request %w", err)
		}

		// Use a func here as we're in a loop and want to make sure the
		// body is closed in all events.
		err = func() error {
			res, err := u.client.Do(req)
			if err != nil {
				return fmt.Errorf("error making advisory request %w", err)
			}
			defer res.Body.Close()
			err = httputil.CheckResponse(res, http.StatusOK)
			if err != nil {
				return fmt.Errorf("unexpected response: %w", err)
			}

			// Add compacted JSON to buffer.
			_, err = buf.ReadFrom(res.Body)
			if err != nil {
				return fmt.Errorf("error reading from buffer: %w", err)
			}
			slog.DebugContext(ctx, "copying body to file", "url", advisoryURI)
			err = json.Compact(&bc, buf.Bytes())
			if err != nil {
				return fmt.Errorf("error compressing JSON: %w", err)
			}

			bc.WriteByte('\n')
			w.Write(bc.Bytes())
			l++
			return nil
		}()
		if !errors.Is(err, nil) {
			return err
		}
	}

	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("error parsing the changes.csv file: %w", err)
	}
	return nil
}

// ProcessDeletions deals with the published deletions.csv, adding records
// to w mean they are deemed to have been deleted since the last compressed
// file was last processed. w and fp can be modified.
func (u *Updater) processDeletions(ctx context.Context, w io.Writer, fp *fingerprint, changed map[string]bool) error {
	deletionURI, err := u.url.Parse(deletionsFile)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deletionURI.String(), nil)
	if err != nil {
		return err
	}
	if fp.deletionsEtag != "" {
		req.Header.Add("If-None-Match", fp.deletionsEtag)
	}
	res, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if t := fp.deletionsEtag; t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("unexpected response from deletions.csv: %s", res.Status)
	}
	fp.deletionsEtag = res.Header.Get("etag")

	rd := csv.NewReader(res.Body)
	rd.FieldsPerRecord = 2
	rd.ReuseRecord = true
	var buf, bc bytes.Buffer

	rec, err := rd.Read()
	for ; err == nil; rec, err = rd.Read() {
		buf.Reset()
		bc.Reset()
		if len(rec) != 2 {
			return fmt.Errorf("could not parse deletions.csv file")
		}

		cvePath, uTime := rec[0], rec[1]
		updatedTime, err := time.Parse(time.RFC3339, uTime)
		if err != nil {
			return err
		}
		if updatedTime.Before(fp.requestTime) {
			continue
		}
		changed[path.Base(cvePath)] = true

		deletedJSON, err := createDeletedJSON(cvePath)
		if err != nil {
			slog.WarnContext(ctx, "error creating JSON object denoting deletion", "reason", err)
		}
		bc.Write(deletedJSON)
		bc.WriteByte('\n')
		w.Write(bc.Bytes())
	}

	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("error parsing the deletions.csv file: %w", err)
	}
	return nil
}

func createDeletedJSON(cvePath string) ([]byte, error) {
	ms := cvePathRegex.FindStringSubmatch(cvePath)
	if len(ms) != 2 {
		return nil, errors.New("failed to parse CVE path")
	}
	j := fmt.Sprintf(deletedTemplate, strings.ToUpper(ms[1]))
	return []byte(j), nil
}
