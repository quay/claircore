package test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/quay/claircore/test/integration"
)

// Main ...
//
// This function panics if any setup fails.
//
//	func MainTest(m *testing.M){
//		test.Main(m)
//	}
func Main(m *testing.M, options ...Option) {
	var code int
	var setup testSetup
	defer func() {
		if err := setup.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "error while cleaning up: %v\n", err)
			code++
		}
		if code != 0 {
			os.Exit(code)
		}
	}()

	flag.Func("app-trace", "path to write for application traces (otel JSON format)", func(arg string) error {
		options = append(options, WithApplicationTrace(arg))
		return nil
	})
	flag.Parse()

	for _, f := range options {
		if err := f(&setup); err != nil {
			panic(err)
		}
	}

	if setup.AppTraceOut != nil {
		// Initialize our stdout exporter, configured to write to a file.
		exporter, err := stdouttrace.New(stdouttrace.WithWriter(setup.AppTraceOut))
		if err != nil {
			panic(fmt.Errorf("creating stdout exporter: %w", err))
		}
		r, err := resource.Merge(
			resource.Default(),
			resource.NewSchemaless(attribute.String("test.start", time.Now().Format(time.RFC3339))))
		if err != nil {
			panic(fmt.Errorf("creating stdout exporter: %w", err))
		}
		// Set the global trace provider configured with that exporter.
		setup.AppTraceProvider = trace.NewTracerProvider(
			trace.WithSampler(trace.AlwaysSample()),
			trace.WithResource(r),
			trace.WithBatcher(exporter),
		)
		otel.SetTracerProvider(setup.AppTraceProvider)

		func() {
			_, span := otel.Tracer("github.com/quay/claircore/test").Start(context.Background(), "Main")
			span.AddEvent("start")
			span.End()
		}()
	}

	code = m.Run()
}

type testSetup struct {
	AppTraceOut      *os.File
	AppTraceProvider *trace.TracerProvider
	DBTeardown       func()
}

// Option is the type for configuring the [Main] funtion.
type Option func(*testSetup) error

// DBSetup arranges for [integration.DBSetup] to be called before tests are run.
func DBSetup(s *testSetup) error {
	s.DBTeardown = integration.DBSetup()
	return nil
}

// WithApplicationTrace arranges for OTel JSON formatted traces to "path".
func WithApplicationTrace(path string) Option {
	return func(s *testSetup) error {
		var prevErr, openErr error
		if s.AppTraceOut != nil {
			fmt.Fprintf(os.Stderr, "closing previously specified trace file: %q", s.AppTraceOut.Name())
			prevErr = s.AppTraceOut.Close()
			s.AppTraceOut = nil
		}
		if path != "" {
			s.AppTraceOut, openErr = os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		}
		return errors.Join(prevErr, openErr)
	}
}

// Close does teardown.
func (s *testSetup) Close() error {
	var errs []error
	if s.DBTeardown != nil {
		s.DBTeardown()
	}
	if s.AppTraceOut != nil {
		// Shut down the trace provider and flush everything.
		timeout, done := context.WithTimeout(context.Background(), 10*time.Second)
		errs = append(errs, s.AppTraceProvider.Shutdown(timeout), s.AppTraceOut.Close())
		done()
	}
	return errors.Join(errs...)
}
