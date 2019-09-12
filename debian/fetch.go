package debian

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
)

// fetch retrieves the xml OVAL database of CVE definitions, takes a sha256 of the xml file, and returns
// an io.ReadCloser with contents.
func (u *Updater) fetch() (io.ReadCloser, string, error) {
	// fetch OVAL xml database
	resp, err := u.c.Get(u.url)
	if err != nil {
		u.logger.Error().Msgf("failed to retrieve OVAL database: %v", err)
		return nil, "", fmt.Errorf("failed to retrieve OVAL database: %v", err)
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
