package tracing

import (
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/api/key"
	trace "go.opentelemetry.io/api/trace"
	"go.opentelemetry.io/exporter/trace/jaeger"
	"go.opentelemetry.io/global"
	sdktrace "go.opentelemetry.io/sdk/trace"
	"google.golang.org/grpc/codes"
)

var (
	provider *sdktrace.Provider
	closers  []func()
)

// Bootstrap creates the required tracer for the HTTP server
func Bootstrap(enabled bool, agentHostPort string) {
	if enabled {
		withJaegerExporter(agentHostPort)
	} else {
		disabled()
	}
}

// GetTracer returns the named tracer, creating it if it doesn't exist yet
func GetTracer(name string) trace.Tracer {
	return provider.GetTracer(name)
}

func disabled() {
	sampling := sdktrace.Config{DefaultSampler: sdktrace.NeverSample()}

	var err error
	provider, err = sdktrace.NewProvider(sdktrace.WithConfig(sampling))
	if err != nil {
		// we don't want the tracing to ever break the server
		log.Warn().Msgf("failed create a new tracing provider: %v", err)
	}

	log.Info().Msg("tracing is disabled")
	global.SetTraceProvider(provider)
}

func withJaegerExporter(agentHostPort string) {
	sampling := sdktrace.Config{DefaultSampler: sdktrace.AlwaysSample()}

	exporter, err := jaeger.NewExporter(
		jaeger.WithAgentEndpoint(agentHostPort),
		jaeger.WithProcess(jaeger.Process{
			ServiceName: "claircore",
		}),
		jaeger.WithOnError(func(err error) {
			log.Error().AnErr("err", err).Msg("failed to setup the Jaeger exporter")
		}),
	)

	closers = append(closers, func() {
		exporter.Flush()
	})

	provider, err = sdktrace.NewProvider(sdktrace.WithConfig(sampling), sdktrace.WithSyncer(exporter))
	if err != nil {
		// we don't want the tracing to ever break the server
		log.Error().AnErr("err", err).Msgf("failed create a new tracing provider")
	}

	log.Info().Msg("tracing is enabled with the Jaeger Exporter")
	global.SetTraceProvider(provider)
}

// Close runs the closer functions collected from all relevant exporters
func Close() {
	for _, c := range closers {
		c()
	}
}

// HandleError sets the span to an error state, storing it s cause in an attribute
func HandleError(err error, span trace.Span) error {
	if err != nil {
		span.SetAttribute(key.String("error", err.Error()))
		span.SetStatus(codes.Internal)
	}
	return err
}
