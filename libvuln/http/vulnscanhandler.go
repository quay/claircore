package http

import (
	"encoding/json"
	"fmt"
	h "net/http"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
	je "github.com/quay/claircore/pkg/jsonerr"
)

func VulnScan(lib libvuln.Libvuln) h.HandlerFunc {
	return func(w h.ResponseWriter, r *h.Request) {
		ctx := r.Context()
		log := zerolog.Ctx(ctx)
		if r.Method != h.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, h.StatusMethodNotAllowed)
			return
		}

		// deserialize IndexReport
		var sr claircore.IndexReport
		err := json.NewDecoder(r.Body).Decode(&sr)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("could not deserialize manifest: %v", err),
			}
			log.Warn().Err(err).Msg("could not deserialize manifest")
			je.Error(w, resp, h.StatusBadRequest)
			return
		}

		// call scan
		vr, err := lib.Scan(ctx, &sr)
		if err != nil {
			resp := &je.Response{
				Code:    "scan-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			log.Warn().Err(err).Msg("failed to start scan")
			je.Error(w, resp, h.StatusInternalServerError)
			return
		}

		err = json.NewEncoder(w).Encode(vr)
		if err != nil {
			// Can't change header or write a different response, because we
			// already started.
			log.Warn().Err(err).Msg("failed to encode response")
		}
		return
	}
}
