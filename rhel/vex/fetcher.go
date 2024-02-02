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
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/httputil"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	compressedFileTimeout = 2 * time.Minute
	deletedTemplate       = `{"document":{"tracking":{"id":"%s","status":"deleted"}}}`
	cvePathRegex          = regexp.MustCompile(`^\d{4}/(cve-\d{4}-\d{4,}).json$`)
)

func (u *Updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/vex/Updater.Fetch")
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
			zlog.Warn(ctx).Err(err).Msg("unable to close snappy writer")
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			zlog.Warn(ctx).
				Err(err).
				Msg("unable to seek file back to start")
		}
		if !success {
			if err := f.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close spool")
			}
		}
	}()

	// Is this the first run or has the updater changed since the last run?
	if fp.changesEtag == "" || fp.version != updaterVersion {
		// We need to go after the full corpus of vulnerabilities
		// First we target the archive_latest.txt file
		latestURI, err := u.url.Parse(latestFile)
		if err != nil {
			return nil, hint, err
		}
		latestReq, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURI.String(), nil)
		if err != nil {
			return nil, hint, err
		}
		latestRes, err := u.client.Do(latestReq)
		if err != nil {
			return nil, hint, err
		}
		defer latestRes.Body.Close()

		err = httputil.CheckResponse(latestRes, http.StatusOK)
		if err != nil {
			return nil, hint, fmt.Errorf("unexpected response from archive_latest.txt: %w", err)
		}

		body, err := io.ReadAll(latestRes.Body) // Fine to use as expecting small number of bytes.
		if err != nil {
			return nil, hint, err
		}

		compressedFilename := string(body)
		zlog.Debug(ctx).
			Str("filename", compressedFilename).
			Msg("requesting latest compressed file")

		uri, err := u.url.Parse(compressedFilename)
		if err != nil {
			return nil, hint, err
		}

		rctx, cancel := context.WithTimeout(ctx, compressedFileTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(rctx, http.MethodGet, uri.String(), nil)
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

		lm := res.Header.Get("last-modified")
		fp.requestTime, err = time.Parse(http.TimeFormat, lm)
		if err != nil {
			return nil, hint, fmt.Errorf("could not parse last-modified header %s: %w", lm, err)
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

		zlog.Debug(ctx).
			Str("updater", u.Name()).
			Int("entries written", entriesWritten).
			Msg("finished writing compressed data to spool")
	}

	err = u.processChanges(ctx, cw, fp)
	if err != nil {
		return nil, hint, err
	}

	err = u.processDeletions(ctx, cw, fp)
	if err != nil {
		return nil, hint, err
	}

	fp.version = updaterVersion
	fp.requestTime = time.Now()
	success = true
	return f, driver.Fingerprint(fp.String()), nil
}

// ProcessChanges deals with the published changes.csv, adding records
// to w means they are deemed to have changed since the compressed
// file was last processed. w and fp can be modified.
func (u *Updater) processChanges(ctx context.Context, w io.Writer, fp *fingerprint) error {
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

	rd := csv.NewReader(res.Body)
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
			zlog.Debug(ctx).Str("url", advisoryURI.String()).Msg("copying body to file")
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
func (u *Updater) processDeletions(ctx context.Context, w io.Writer, fp *fingerprint) error {
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
		deletedJSON, err := createDeletedJSON(cvePath)
		if err != nil {
			zlog.Warn(ctx).Err(err).Msg("error creating JSON object denoting deletion")
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
