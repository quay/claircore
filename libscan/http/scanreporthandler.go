package http

import (
	"encoding/json"
	"fmt"
	"log"
	h "net/http"
	"strings"

	"github.com/quay/claircore/libscan"
)

func ScanReport(lib libscan.Libscan) h.HandlerFunc {
	return func(w h.ResponseWriter, r *h.Request) {
		if r.Method != h.MethodGet {
			h.Error(w, "endpoint only allows GET", h.StatusMethodNotAllowed)
			return
		}

		// extract manifest from path
		hash := strings.TrimPrefix(r.URL.Path, "/scanreport/")
		if hash == "" {
			h.Error(w, "could not find manifest hash in path", h.StatusBadRequest)
			return
		}

		// issue retrieval
		sr, ok, err := lib.ScanReport(hash)
		if err != nil {
			h.Error(w, fmt.Sprintf("error receiving scanreport"), h.StatusInternalServerError)
			log.Printf("failed to retrieve scanreport for %v: %v", hash, err)
			return
		}

		if !ok {
			h.Error(w, fmt.Sprintf("scan report for %v does not exist", hash), h.StatusNotFound)
			return
		}

		// serialize and return scanresult
		err = json.NewEncoder(w).Encode(sr)
		if err != nil {
			h.Error(w, "could not return scan report", h.StatusInternalServerError)
			log.Printf("failed to return scanreport for %v: %v", hash, err)
			return
		}
	}
}
