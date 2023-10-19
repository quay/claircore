package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"
	"text/tabwriter"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/quay/claircore/test/integration"
)

func TestMain(m *testing.M) {
	traceout := flag.String("traces", "", "write JSON-formatted trace to the specified file")
	metrics := flag.Bool("metrics", false, "write metrics to stdout")
	flag.Parse()
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	if *traceout != "" {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			println("otel error: ", err.Error())
		}))
		t, err := os.Create(*traceout)
		if err != nil {
			println("trace setup error:", err.Error())
		} else {
			defer t.Close()
			defer t.Sync()
			tp, err := stdouttrace.New(stdouttrace.WithWriter(t))
			if err != nil {
				println("trace setup error:", err.Error())
			} else {
				tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(tp), sdktrace.WithSampler(sdktrace.AlwaysSample()))
				otel.SetTracerProvider(tp)
				defer tp.Shutdown(context.Background())
			}
		}
	}
	if *metrics {
		enc := json.NewEncoder(os.Stdout)
		exp, err := stdoutmetric.New(stdoutmetric.WithEncoder(enc))
		if err != nil {
			panic(err)
		}
		mp := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp)))
		otel.SetMeterProvider(mp)
		defer mp.Shutdown(context.Background())
	}
	c = m.Run()
}

func dumptable(ctx context.Context, t *testing.T, pool *pgxpool.Pool, relname string) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	defer func() {
		w.Flush()
		t.Logf("dump %q:\n%s", relname, buf.String())
	}()
	rows, err := pool.Query(ctx, fmt.Sprintf("SELECT * FROM %s;", pgx.Identifier{relname}.Sanitize()))
	if err != nil {
		t.Error(err)
		return
	}
	defer rows.Close()
	for i, desc := range rows.FieldDescriptions() {
		if i != 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, desc.Name)
	}
	fmt.Fprintln(w)
	for rows.Next() {
		vs, err := rows.Values()
		if err != nil {
			t.Error(err)
			return
		}
		for i, arg := range vs {
			if i != 0 {
				fmt.Fprint(w, "\t")
			}
			fmt.Fprintf(w, "%v", arg)
		}
		fmt.Fprintln(w)
	}
	if err := rows.Err(); err != nil {
		t.Error(err)
	}
}
