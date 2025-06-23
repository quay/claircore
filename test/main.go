package test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/test/integration"
)

// Main ...
//
// Having "OTEL_TRACES_EXPORTER" or "OTEL_METRICS_EXPORTER" set to "otlp" in the
// environment will trigger setup for the respective signal automatically.
//
// The environment variable "OTEL_EXPORTER_OTLP_PROTOCOL" can be set to "grpc"
// or "http/protobuf" (default) to control the protocol. The default OTLP
// endpoint is configured to use "http" instead of "https".
//
// See [Traces] and [Metrics] for additional configuration information.
//
// This function panics if any setup fails.
//
//	func MainTest(m *testing.M){
//		test.Main(m)
//	}
func Main(m *testing.M, options ...Option) {
	start := time.Now()
	var code int
	defer func() {
		if code != 0 {
			os.Exit(code)
		}
	}()

	otlpEnv := false
	if os.Getenv(`OTEL_TRACES_EXPORTER`) == "otlp" {
		otlpEnv = true
		options = append(options, Traces)
	}
	if os.Getenv(`OTEL_METRICS_EXPORTER`) == "otlp" {
		otlpEnv = true
		options = append(options, Metrics)
	}
	if os.Getenv(`OTEL_LOGS_EXPORTER`) == "otlp" {
		otlpEnv = true
		options = append(options, OtlpLogs)
	}
	// Use a nicer default for tests:
	key := `OTEL_EXPORTER_OTLP_ENDPOINT`
	if _, ok := os.LookupEnv(key); otlpEnv && !ok {
		var value string
		switch getProto() {
		case otlpProtoGRPC:
			value = "http://localhost:4317"
		case otlpProtoHTTP:
			value = "http://localhost:4318"
		}
		os.Setenv(key, value)
	}

	ctx := context.Background()
	for _, f := range options {
		if err := f(ctx, &mainSetup); err != nil {
			panic(err)
		}
	}

	ctx, span := otel.
		Tracer("github.com/quay/claircore/test").
		Start(ctx, "Main",
			trace.WithNewRoot(),
			trace.WithSpanKind(trace.SpanKindConsumer),
			trace.WithTimestamp(start),
		)
	mainSetup.RootSpan = span

	code = m.Run()

	// Cannot call these functions before [testing.M.Run].
	span.SetAttributes(
		attribute.Bool("testing.short", testing.Short()),
		attribute.Bool("testing.verbose", testing.Verbose()),
	)
	trCode := codes.Ok
	if code != 0 {
		trCode = codes.Error
	}
	span.SetStatus(trCode, "")
	span.End()

	if err := mainSetup.Close(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error while cleaning up: %v\n", err)
		code++
	}
}

var mainSetup testSetup

type testSetup struct {
	TraceProvider  *sdktrace.TracerProvider
	MeterProvider  *sdkmetric.MeterProvider
	LoggerProvider *sdklog.LoggerProvider
	DBTeardown     func()
	RootSpan       trace.Span
}

// Option is the type for configuring the [Main] funtion.
type Option func(context.Context, *testSetup) error

// DBSetup arranges for [integration.DBSetup] to be called before tests are run.
func DBSetup(_ context.Context, s *testSetup) error {
	s.DBTeardown = integration.DBSetup()
	return nil
}

// Traces arranges for an OTLP exporter to be configured according to the
// environment.
//
// See the documentation for
// [go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp] and
// [go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc] for
// additional environment variables.
func Traces(ctx context.Context, s *testSetup) error {
	if s.TraceProvider != nil {
		return nil
	}
	var c otlptrace.Client
	switch getProto() {
	case otlpProtoGRPC:
		c = otlptracegrpc.NewClient()
	case otlpProtoHTTP:
		c = otlptracehttp.NewClient()
	}
	exporter, err := otlptrace.New(ctx, c)
	if err != nil {
		return fmt.Errorf("creating OTLP exporter: %w", err)
	}
	r, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", srvName()),
			attribute.String("test.start", time.Now().Format(time.RFC3339)),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP resource: %w", err)
	}
	// Set the global trace provider configured with that exporter.
	s.TraceProvider = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(r),
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(s.TraceProvider)

	return nil
}

// Metrics arranges for an OTLP exporter to be configured according to the
// environment.
//
// See the documentation for
// [go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp] and
// [go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc] for
// additional environment variables.
func Metrics(ctx context.Context, s *testSetup) error {
	if s.MeterProvider != nil {
		return nil
	}
	var rd *sdkmetric.PeriodicReader
	switch getProto() {
	case otlpProtoGRPC:
		e, err := otlpmetricgrpc.New(ctx)
		if err != nil {
			return fmt.Errorf("unable to create exporter: %w", err)
		}
		rd = sdkmetric.NewPeriodicReader(e)
	case otlpProtoHTTP:
		e, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return fmt.Errorf("unable to create exporter: %w", err)
		}
		rd = sdkmetric.NewPeriodicReader(e)
	}

	r, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", srvName()),
			attribute.String("test.start", time.Now().Format(time.RFC3339)),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP resource: %w", err)
	}

	s.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(r), sdkmetric.WithReader(rd))
	otel.SetMeterProvider(s.MeterProvider)

	m, err := otel.Meter("github.com/quay/claircore/test").Int64Counter("start")
	if err != nil {
		return fmt.Errorf("creating OTLP metric: %w", err)
	}
	m.Add(ctx, 1)

	return nil
}

func OtlpLogs(ctx context.Context, s *testSetup) error {
	if s.LoggerProvider != nil {
		return nil
	}

	var p sdklog.Processor
	switch getProto() {
	case otlpProtoGRPC:
		e, err := otlploggrpc.New(ctx)
		if err != nil {
			return fmt.Errorf("unable to create exporter: %w", err)
		}
		p = sdklog.NewSimpleProcessor(e)
	case otlpProtoHTTP:
		e, err := otlploghttp.New(ctx)
		if err != nil {
			return fmt.Errorf("unable to create exporter: %w", err)
		}
		p = sdklog.NewSimpleProcessor(e)
	}

	r, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", srvName()),
			attribute.String("test.start", time.Now().Format(time.RFC3339)),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP resource: %w", err)
	}

	s.LoggerProvider = sdklog.NewLoggerProvider(sdklog.WithResource(r), sdklog.WithProcessor(p))
	global.SetLoggerProvider(s.LoggerProvider)

	return nil
}

var (
	srvName = sync.OnceValue(func() string {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			return "claircore_test"
		}
		return bi.Path
	})
	getProto = sync.OnceValue(func() otlpProto {
		proto := os.Getenv(`OTEL_EXPORTER_OTLP_PROTOCOL`)
		switch proto {
		case "grpc":
			return otlpProtoGRPC
		case "", "http/protobuf":
			return otlpProtoHTTP
		default:
			panic(fmt.Errorf("unrecognized OTLP protocol: %q", proto))
		}
	})
)

type otlpProto uint

const (
	otlpProtoHTTP otlpProto = iota
	otlpProtoGRPC
)

// Close does teardown.
func (s *testSetup) Close(ctx context.Context) error {
	ctx, span := otel.
		Tracer("github.com/quay/claircore/test").
		Start(ctx, "setup.Close")
	defer span.End()

	if s.DBTeardown != nil {
		s.DBTeardown()
	}
	timeout, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()

	return errors.Join(
		func() error {
			if s.TraceProvider != nil {
				return s.TraceProvider.Shutdown(timeout)
			}
			return nil
		}(),
		func() error {
			if s.MeterProvider != nil {
				return s.MeterProvider.Shutdown(timeout)
			}
			return nil
		}(),
		func() error {
			if s.LoggerProvider != nil {
				return s.LoggerProvider.Shutdown(timeout)
			}
			return nil
		}(),
	)
}

func RootContext(t testing.TB) context.Context {
	ctx := context.Background()
	ctx = trace.ContextWithSpan(ctx, mainSetup.RootSpan)
	ctx = Logging(t, ctx)
	return ctx
}
