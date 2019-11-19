package http

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"strings"

	"github.com/quay/claircore/libindex"

	"github.com/rs/zerolog/log"
)

func IndexReport(lib libindex.Libindex) h.HandlerFunc {
	return func(w h.ResponseWriter, r *h.Request) {
		ctx := r.Context()
		log := log.Logger
		if r.Method != h.MethodGet {
			const msg = "endpoint only allows GET"
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusMethodNotAllowed)
			return
		}

		// extract manifest from path
		hash := strings.TrimPrefix(r.URL.Path, "/index_report/")
		if hash == "" {
			const msg = "could not find manifest hash in path"
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusBadRequest)
			return
		}

		// issue retrieval
		sr, ok, err := lib.IndexReport(ctx, hash)
		if err != nil {
			const msg = "error receiving scan report"
			log.Warn().Err(err).Msg(msg)
			h.Error(w, msg, h.StatusInternalServerError)
			return
		}

		if !ok {
			msg := fmt.Sprintf("scan report for %v does not exist", hash)
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusNotFound)
			return
		}

		// serialize and return scanresult
		err = json.NewEncoder(w).Encode(sr)
		if err != nil {
			const msg = "could not return scan report"
			log.Warn().Err(err).Msg(msg)
			h.Error(w, msg, h.StatusInternalServerError)
			return
		}
	}
}
