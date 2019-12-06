package ubuntu

import (
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// fetchBzip retrieves a bzip compressed OVAL database of CVE definitions, takes a
// sha256 hash of the bzip'd archive, and returns a io.ReadCloser of the uncompressed contents
func (u *Updater) fetchBzip(ctx context.Context) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request")
	}

	// fetch OVAL xml database
	resp, err := u.c.Do(req)
	if err != nil {
		u.logger.Error().Msgf("failed to retrieve OVAL database: %v", err)
		return nil, "", fmt.Errorf("failed to retrieve OVAL database: %v", err)
	}

	// check resp
	if resp.StatusCode <= 199 && resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("http request returned non-200: %v %v", resp.StatusCode, resp.Status)
	}

	// copy into byte array
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		u.logger.Error().Msgf("failed to read http body: %v", err)
		return nil, "", fmt.Errorf("failed to read http body: %v", err)
	}

	// take sha256 hash
	sum := sha256.Sum256(b)

	// return a NopCloser from a bzip reader
	r := bytes.NewReader(b)
	bzipR := bzip2.NewReader(r)
	rc := ioutil.NopCloser(bzipR)

	return rc, fmt.Sprintf("%x", sum), nil
}

// fetch retrieves the xml OVAL database of CVE definitions, takes a sha256 of the xml file, and returns
// an io.ReadCloser with contents.
func (u *Updater) fetch(ctx context.Context) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request")
	}

	// fetch OVAL xml database
	resp, err := u.c.Do(req)
	if err != nil {
		u.logger.Error().Msgf("failed to retrieve OVAL database: %v", err)
		return nil, "", fmt.Errorf("failed to retrieve OVAL database: %v", err)
	}

	// check resp
	if resp.StatusCode <= 199 && resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("http request returned non-200: %v %v", resp.StatusCode, resp.Status)
	}

	// copy into byte array
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		u.logger.Error().Msgf("failed to read http body: %v", err)
		return nil, "", fmt.Errorf("failed to read http body: %v", err)
	}

	// take sha256 hash
	sum := sha256.Sum256(b)

	// return a NopCloser from byte array
	r := bytes.NewReader(b)
	rc := ioutil.NopCloser(r)
	return rc, fmt.Sprintf("%x", sum), nil
}
