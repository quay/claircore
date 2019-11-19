package http

import (
	"context"
	"encoding/json"
	"fmt"
	h "net/http"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
	je "github.com/quay/claircore/pkg/jsonerr"
)

// Scan returns an http.HandlerFunc which will
// kick off a Scan of the POST'd manifest
func Scan(lib libindex.Libindex) h.HandlerFunc {
	return func(w h.ResponseWriter, r *h.Request) {
		if r.Method != h.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, h.StatusMethodNotAllowed)
			return
		}

		// deserialize manifest
		var m claircore.Manifest
		err := json.NewDecoder(r.Body).Decode(&m)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("could not deserialize manifest: %v", err),
			}
			je.Error(w, resp, h.StatusBadRequest)
			return
		}

		// call scan
		_, err = lib.Scan(context.Background(), &m)
		if err != nil {
			resp := &je.Response{
				Code:    "scan-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			je.Error(w, resp, h.StatusInternalServerError)
			return
		}

		// sleep here to give time for scanner to push first state
		// we could have the returned channel send *all* changes of the
		// scan report to the channel, range over, and send break out of the range
		// on the first retrieval.
		time.Sleep(1 * time.Second)

		h.Redirect(w, r, fmt.Sprintf("/scanreport/%s", m.Hash), h.StatusMovedPermanently)

		return
	}
}
