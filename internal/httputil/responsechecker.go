package httputil

import (
	"fmt"
	"io"
	"net/http"
	"slices"
)

// CheckResponse takes a http.Response and a variadic of ints representing
// acceptable http status codes. The error returned will attempt to include
// some content from the server's response.
func CheckResponse(resp *http.Response, acceptableCodes ...int) error {
	acceptable := slices.Contains(acceptableCodes, resp.StatusCode)
	if !acceptable {
		limitBody, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		if err == nil {
			return fmt.Errorf("unexpected status code: %s (body starts: %q)", resp.Status, limitBody)
		}
		return fmt.Errorf("unexpected status code: %s", resp.Status)
	}
	return nil
}
