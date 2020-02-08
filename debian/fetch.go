package debian

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

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
		return nil, "", fmt.Errorf("failed to retrieve OVAL database: %v", err)
	}

	// check resp
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("http request returned non-200: %v %v", resp.StatusCode, resp.Status)
	}

	// copy into byte array
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read http body: %v", err)
	}

	// take sha256 hash
	sum := sha256.Sum256(b)

	// return a NopCloser from byte array
	r := bytes.NewReader(b)
	rc := ioutil.NopCloser(r)
	return rc, fmt.Sprintf("%x", sum), nil
}
