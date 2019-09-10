package http

import (
	"encoding/json"
	"fmt"
	"log"
	h "net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
	je "github.com/quay/claircore/pkg/jsonerr"
)

func VulnScan(lib libvuln.Libvuln) h.HandlerFunc {
	return func(w h.ResponseWriter, r *h.Request) {
		if r.Method != h.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, h.StatusMethodNotAllowed)
			return
		}

		// deserialize ScanReport
		var sr claircore.ScanReport
		err := json.NewDecoder(r.Body).Decode(&sr)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("could not deserialize manifest: %v", err),
			}
			log.Printf("could not deserialize manifest: %v", err)
			je.Error(w, resp, h.StatusBadRequest)
			return
		}

		// call scan
		vr, err := lib.Scan(r.Context(), &sr)
		if err != nil {
			resp := &je.Response{
				Code:    "scan-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			je.Error(w, resp, h.StatusInternalServerError)
			return
		}

		err = json.NewEncoder(w).Encode(vr)
		if err != nil {
			resp := &je.Response{
				Code:    "scan-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			je.Error(w, resp, h.StatusInternalServerError)
			return
		}

		return
	}
}
