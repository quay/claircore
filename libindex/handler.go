package libindex

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = (*HTTP)(nil)

type HTTP struct {
	*http.ServeMux
	l *Libindex
}

func NewHandler(l *Libindex) *HTTP {
	h := &HTTP{l: l}
	m := http.NewServeMux()
	m.Handle("/index", http.HandlerFunc(h.Index))
	m.Handle("/index/", http.HandlerFunc(h.IndexReport))
	m.Handle("/state", http.HandlerFunc(h.State))
	h.ServeMux = m
	return h
}

func (h *HTTP) State(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	fmt.Fprintln(w, h.l.State())
}

func (h *HTTP) Index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx).With().
		Str("method", "index").
		Logger()
	ctx = log.WithContext(ctx)
	if r.Method != http.MethodPost {
		resp := &jsonerr.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows POST",
		}
		jsonerr.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	// deserialize manifest
	var m claircore.Manifest
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		resp := &jsonerr.Response{
			Code:    "bad-request",
			Message: fmt.Sprintf("could not deserialize manifest: %v", err),
		}
		log.Debug().Err(err).Msg("could not deserialize manifest")
		jsonerr.Error(w, resp, http.StatusBadRequest)
		return
	}

	// call scan
	ir, err := h.l.Index(ctx, &m)
	if err != nil {
		resp := &jsonerr.Response{
			Code:    "scan-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		log.Error().
			Err(err).
			Msg("failed to start scan")
		jsonerr.Error(w, resp, http.StatusInternalServerError)
		return
	}

	w.Header().Set("location", path.Join(r.URL.Path, m.Hash))
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(&ir); err != nil {
		log.Error().Err(err).Msg("failed to serialize results")
	}
	return
}

func (h *HTTP) IndexReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx).With().
		Str("method", "index_report").
		Logger()
	// Added to Context later.
	if r.Method != http.MethodGet {
		resp := &jsonerr.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		jsonerr.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	// extract manifest from path
	hash := path.Base(r.URL.Path)
	if hash == "" {
		resp := &jsonerr.Response{
			Code:    "bad-request",
			Message: "could not find manifest hash in path",
		}
		log.Debug().Str("path", r.URL.Path).Msg(resp.Message)
		jsonerr.Error(w, resp, http.StatusBadRequest)
		return
	}
	log = log.With().Str("hash", hash).Logger()
	ctx = log.WithContext(ctx)

	// issue retrieval
	sr, ok, err := h.l.IndexReport(ctx, hash)
	if err != nil {
		const msg = "error receiving index report"
		resp := &jsonerr.Response{
			Code:    "index-report",
			Message: msg,
		}
		log.Warn().Err(err).Msg(msg)
		jsonerr.Error(w, resp, http.StatusInternalServerError)
		return
	}

	if !ok {
		resp := &jsonerr.Response{
			Code:    "not-found",
			Message: fmt.Sprintf("index report for %v does not exist", hash),
		}
		log.Debug().Msg("index report does not exist")
		jsonerr.Error(w, resp, http.StatusNotFound)
		return
	}

	w.Header().Set("content-type", "application/json")
	// serialize and return scanresult
	if err = json.NewEncoder(w).Encode(sr); err != nil {
		const msg = "could not return index report"
		log.Error().Err(err).Msg(msg)
		// Too late to change our header, now.
	}
}
