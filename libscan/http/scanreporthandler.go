package http

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"strings"

	"github.com/quay/claircore/libscan"
	"github.com/quay/claircore/pkg/tracing"
	"go.opentelemetry.io/api/key"
	"google.golang.org/grpc/codes"

	"github.com/rs/zerolog/log"
)

func ScanReport(lib libscan.Libscan) h.HandlerFunc {
	tracer := tracing.GetTracer("claircore/http/ScanReport")

	return func(w h.ResponseWriter, r *h.Request) {
		ctx, span := tracer.Start(r.Context(), "ScanReport")
		defer span.End()

		log := log.Logger
		if r.Method != h.MethodGet {
			const msg = "endpoint only allows GET"
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusMethodNotAllowed)
			span.SetAttribute(key.String("error", msg))
			span.SetStatus(codes.FailedPrecondition)
			return
		}

		// extract manifest from path
		hash := strings.TrimPrefix(r.URL.Path, "/scanreport/")
		if hash == "" {
			const msg = "could not find manifest hash in path"
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusBadRequest)
			span.SetAttribute(key.String("error", msg))
			span.SetStatus(codes.InvalidArgument)
			return
		}

		// issue retrieval
		sr, ok, err := lib.ScanReport(ctx, hash)
		if err != nil {
			const msg = "error receiving scan report"
			log.Warn().Err(err).Msg(msg)
			h.Error(w, msg, h.StatusInternalServerError)
			tracing.HandleError(err, span)
			return
		}

		if !ok {
			msg := fmt.Sprintf("scan report for %v does not exist", hash)
			log.Info().Msg(msg)
			h.Error(w, msg, h.StatusNotFound)
			span.SetAttribute(key.String("error", msg))
			span.SetStatus(codes.NotFound)
			return
		}

		// serialize and return scanresult
		err = json.NewEncoder(w).Encode(sr)
		if err != nil {
			const msg = "could not return scan report"
			log.Warn().Err(err).Msg(msg)
			h.Error(w, msg, h.StatusInternalServerError)
			tracing.HandleError(err, span)
			return
		}
	}
}
