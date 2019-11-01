package http

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libscan"
	je "github.com/quay/claircore/pkg/jsonerr"
	"github.com/quay/claircore/pkg/tracing"
	"go.opentelemetry.io/api/key"
	"google.golang.org/grpc/codes"
)

// Scan returns an http.HandlerFunc which will
// kick off a Scan of the POST'd manifest
func Scan(lib libscan.Libscan) h.HandlerFunc {
	tracer := tracing.GetTracer("claircore/http/Scan")

	return func(w h.ResponseWriter, r *h.Request) {
		ctx, span := tracer.Start(r.Context(), "Scan")
		defer span.End()

		if r.Method != h.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, h.StatusMethodNotAllowed)
			span.SetAttribute(key.String("error", resp.Message))
			span.SetStatus(codes.FailedPrecondition)
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
			span.SetAttribute(key.String("error", err.Error()))
			span.SetStatus(codes.InvalidArgument)
			return
		}

		// call scan
		_, err = lib.Scan(ctx, &m)
		if err != nil {
			resp := &je.Response{
				Code:    "scan-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			je.Error(w, resp, h.StatusInternalServerError)
			tracing.HandleError(err, span)
			return
		}

		// sleep here to give time for scanner to push first state
		// we could have the returned channel send *all* changes of the
		// scan report to the channel, range over, and send break out of the range
		// on the first retrieval.
		time.Sleep(1 * time.Second)

		span.SetStatus(codes.OK)
		span.SetAttribute(key.String("report", m.Hash))
		h.Redirect(w, r, fmt.Sprintf("/scanreport/%s", m.Hash), h.StatusMovedPermanently)

		return
	}
}
