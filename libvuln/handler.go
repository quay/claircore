package libvuln

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	je "github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = (*HTTP)(nil)

type HTTP struct {
	*http.ServeMux
	l *Libvuln
}

func NewHandler(l *Libvuln) *HTTP {
	h := &HTTP{l: l}
	m := http.NewServeMux()
	m.HandleFunc("/vulnerability_report", h.VulnerabilityReport)
	m.HandleFunc("/update_operation", h.UpdateOperations)
	m.HandleFunc("/update_diff", h.UpdateDiff)
	h.ServeMux = m
	return h
}

func (h *HTTP) UpdateDiff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}
	// prev param is optional.
	var prev uuid.UUID
	var err error
	if param, ok := r.URL.Query()["prev"]; ok {
		if len(param) != 0 {
			prev, err = uuid.Parse(param[0])
			if err != nil {
				resp := &je.Response{
					Code:    "bad-request",
					Message: "could not parse \"prev\" query param into uuid",
				}
				je.Error(w, resp, http.StatusBadRequest)
				return
			}
		}
	}
	// cur param is required
	var cur uuid.UUID
	param, ok := r.URL.Query()["cur"]
	if !ok || len(param) == 0 {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "cur query param is required",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}
	if cur, err = uuid.Parse(param[0]); err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "could not parse \"cur query param into uuid",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	diff, err := h.l.UpdateDiff(ctx, prev, cur)
	if err != nil {
		resp := &je.Response{
			Code:    "internal server error",
			Message: fmt.Sprintf("could not get update operations: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(&diff)
	if err != nil {
		// Can't change header or write a different response, because we
		// already started.
		zlog.Warn(ctx).Err(err).Msg("failed to encode response")
	}
}

func (h *HTTP) UpdateOperations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		var latest string
		if param, ok := r.URL.Query()["latest"]; ok {
			if len(param) != 0 {
				latest = param[0]
			}
		}
		var uos map[string][]driver.UpdateOperation
		var err error
		if b, _ := strconv.ParseBool(latest); b {
			uos, err = h.l.LatestUpdateOperations(ctx, driver.VulnerabilityKind)
		} else {
			uos, err = h.l.UpdateOperations(ctx, driver.VulnerabilityKind)
		}
		if err != nil {
			resp := &je.Response{
				Code:    "internal server error",
				Message: fmt.Sprintf("could not get update operations: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}
		err = json.NewEncoder(w).Encode(&uos)
		if err != nil {
			// Can't change header or write a different response, because we
			// already started.
			zlog.Warn(ctx).Err(err).Msg("failed to encode response")
		}
		return

	case http.MethodDelete:
		path := r.URL.Path
		id := filepath.Base(path)
		uuid, err := uuid.Parse(id)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("could not deserialize manifest: %v", err),
			}
			zlog.Warn(ctx).Err(err).Msg("could not deserialize manifest")
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		_, err = h.l.DeleteUpdateOperations(ctx, uuid)
		if err != nil {
			resp := &je.Response{
				Code:    "internal server error",
				Message: fmt.Sprintf("could not delete update operations: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

	default:
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET and DELETE",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}
}

func (h *HTTP) VulnerabilityReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows POST",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
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
		zlog.Warn(ctx).Err(err).Msg("could not deserialize manifest")
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	// call scan
	vr, err := h.l.Scan(ctx, &sr)
	if err != nil {
		resp := &je.Response{
			Code:    "scan-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		zlog.Warn(ctx).Err(err).Msg("failed to start scan")
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(vr)
	if err != nil {
		// Can't change header or write a different response, because we
		// already started.
		zlog.Warn(ctx).Err(err).Msg("failed to encode response")
	}
	return
}
