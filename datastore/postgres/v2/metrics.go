package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// TelemetrySchemaVersion is the OpenTelemetry "telemetry schema" version for this package.
// See the [Telemetry Schemas] documentation for more information.
//
// BUG(hank) The telemetry exported by this package does not have a schema yet.
//
// TODO(hank) Export this name when we have something set up for this.
//
// [Telemetry Schemas]: https://opentelemetry.io/docs/specs/otel/schemas/
const telemetrySchemaVersion = `0.1.0`

// Tracer and Meter singletons for this package.
var (
	tracer trace.Tracer
	meter  metric.Meter
)

// The instruments used in this package.
var (
	methodCount    metric.Int64Counter
	methodDuration metric.Int64Histogram
	callCounter    metric.Int64Counter
	callDuration   metric.Int64Histogram

	// These are as specified in
	// https://opentelemetry.io/docs/specs/semconv/database/database-metrics/.
	poolUsage      metric.Int64ObservableUpDownCounter
	poolIdleMax    metric.Int64UpDownCounter
	poolIdleMin    metric.Int64UpDownCounter
	poolMax        metric.Int64UpDownCounter
	poolPending    metric.Int64ObservableUpDownCounter
	poolTimeout    metric.Int64ObservableCounter
	poolCreateTime metric.Int64Histogram
	poolWaitTime   metric.Int64Histogram
	poolUseTime    metric.Int64Histogram
)

// Must is a panic-or-return helper for [init].
func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func init() {
	tracer = otel.Tracer("github.com/quay/claircore/datastore/postgres/v2",
		trace.WithInstrumentationVersion(telemetrySchemaVersion),
	)
	meter = otel.Meter("github.com/quay/claircore/datastore/postgres/v2",
		metric.WithInstrumentationVersion(telemetrySchemaVersion),
	)

	methodCount = must(meter.Int64Counter("method.calls",
		metric.WithDescription("The number of calls for the method described by the method attribute."),
		metric.WithUnit("{call}"),
	))
	methodDuration = must(meter.Int64Histogram("method.call_time",
		metric.WithDescription("The duration of calls for the method described by the method attribute."),
		metric.WithUnit("ms"),
	))

	poolUsage = must(meter.Int64ObservableUpDownCounter("db.client.connections.usage",
		metric.WithDescription("The number of connections that are currently in state described by the state attribute."),
		metric.WithUnit("{connection}"),
	))
	poolIdleMax = must(meter.Int64UpDownCounter("db.client.connections.idle.max",
		metric.WithDescription("The maximum number of idle open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolIdleMin = must(meter.Int64UpDownCounter("db.client.connections.idle.min",
		metric.WithDescription("The minimum number of idle open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolMax = must(meter.Int64UpDownCounter("db.client.connections.max",
		metric.WithDescription("The maximum number of open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolPending = must(meter.Int64ObservableUpDownCounter("db.client.connections.pending_requests",
		metric.WithDescription("The number of pending requests for an open connection, cumulative for the entire pool."),
		metric.WithUnit("{request}"),
	))
	poolTimeout = must(meter.Int64ObservableCounter("db.client.connections.timeouts",
		metric.WithDescription("The number of connection timeouts that have occurred trying to obtain a connection from the pool."),
		metric.WithUnit("{timeout}"),
	))
	poolCreateTime = must(meter.Int64Histogram("db.client.connections.create_time",
		metric.WithDescription("The time it took to create a new connection."),
		metric.WithUnit("ms"),
	))
	poolWaitTime = must(meter.Int64Histogram("db.client.connections.wait_time",
		metric.WithDescription("The time it took to obtain an open connection from the pool."),
		metric.WithUnit("ms"),
	))
	poolUseTime = must(meter.Int64Histogram("db.client.connections.use_time",
		metric.WithDescription("The time between borrowing a connection and returning it to the pool."),
		metric.WithUnit("ms"),
	))
}

// PgpidAttr is a helper for constructing an attribute for the provided
// connection's server PID.
func pgpidAttr(c *pgx.Conn) attribute.KeyValue {
	return attribute.Int("postgresql.pid", int(c.PgConn().PID()))
}

// DbAffected is the key used to record the rows affected by a query.
var dbAffected = attribute.Key("db.rows_affected")

var dbBatchSize = attribute.Key("db.batch_total")

type poolTracer struct {
	metricAttrs attribute.Set
}

// Static assertions that [*poolTracer] implements all the interfaces needed:
var (
	_ pgx.BatchTracer    = (*poolTracer)(nil)
	_ pgx.ConnectTracer  = (*poolTracer)(nil)
	_ pgx.CopyFromTracer = (*poolTracer)(nil)
	_ pgx.PrepareTracer  = (*poolTracer)(nil)
	_ pgx.QueryTracer    = (*poolTracer)(nil)
)

var (
	connectKey  = ctxKey{}
	copyfromKey = ctxKey{}
	queryKey    = ctxKey{}
	batchKey    = ctxKey{}
)

type traceBatch struct {
	Begin    time.Time
	Attrs    []attribute.KeyValue
	Affected int64
}

// TraceBatchStart implements [pgx.BatchTracer].
func (t *poolTracer) TraceBatchStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	return context.WithValue(ctx, batchKey, &traceBatch{
		Begin: time.Now(),
		Attrs: []attribute.KeyValue{
			dbBatchSize.Int(data.Batch.Len()),
			pgpidAttr(conn),
		},
	})
}

// TraceBatchQuery implements [pgx.BatchTracer].
func (t *poolTracer) TraceBatchQuery(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchQueryData) {
	q := ctx.Value(queryKey).(*traceBatch)
	affected := data.CommandTag.RowsAffected()
	dur := time.Since(q.Begin)

	poolUseTime.Record(ctx, dur.Milliseconds(), metric.WithAttributeSet(t.metricAttrs))
	q.Affected += affected
	if err := data.Err; err != nil {
		zlog.Debug(ctx).Err(err).Msg("batch query error")
	}
}

// TraceBatchEnd implements [pgx.BatchTracer].
func (t *poolTracer) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchEndData) {
	q := ctx.Value(queryKey).(*traceBatch)
	dur := time.Since(q.Begin)

	poolUseTime.Record(ctx, dur.Milliseconds(), metric.WithAttributeSet(t.metricAttrs))
	ev := zlog.Debug(ctx).
		Int64("affected", q.Affected).
		Dur("duration_ms", dur)
	err := data.Err
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	if err != nil {
		span.SetStatus(codes.Error, "batch error")
		ev = ev.Err(err)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	ev.Msg("batch done")
}

// TraceConnectStart implements [pgx.ConnectTracer].
func (t *poolTracer) TraceConnectStart(ctx context.Context, _ pgx.TraceConnectStartData) context.Context {
	return context.WithValue(ctx, connectKey, time.Now())
}

// TraceConnectEnd implements [pgx.ConnectTracer].
func (t *poolTracer) TraceConnectEnd(ctx context.Context, _ pgx.TraceConnectEndData) {
	start := ctx.Value(connectKey).(time.Time)
	poolCreateTime.Record(ctx, time.Since(start).Milliseconds(), metric.WithAttributeSet(t.metricAttrs))
}

type traceCopy struct {
	Begin time.Time
	Attrs []attribute.KeyValue
}

// TraceCopyFromStart implements [pgx.CopyFromTracer].
func (t *poolTracer) TraceCopyFromStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	return context.WithValue(ctx, copyfromKey, &traceCopy{
		Begin: time.Now(),
		Attrs: []attribute.KeyValue{
			semconv.DBSQLTable(data.TableName.Sanitize()),
			pgpidAttr(conn),
		},
	})
}

// TraceCopyFromEnd implements [pgx.CopyFromTracer].
func (t *poolTracer) TraceCopyFromEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromEndData) {
	q := ctx.Value(queryKey).(*traceCopy)
	op, affected := strings.TrimRight(data.CommandTag.String(), ` 0123456789`), data.CommandTag.RowsAffected()
	dur := time.Since(q.Begin)

	poolUseTime.Record(ctx, dur.Milliseconds(), metric.WithAttributeSet(t.metricAttrs))
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(append(q.Attrs, semconv.DBOperation(op), dbAffected.Int64(affected))...)
	ev := zlog.Debug(ctx).
		Str("operation", op).
		Int64("affected", affected).
		Dur("duration_ms", dur)
	err := data.Err
	span.RecordError(err)
	if err != nil {
		span.SetStatus(codes.Error, "query error")
		ev = ev.Err(err)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	ev.Msg("copy done")
}

// TracePrepareStart implements [pgx.PrepareTracer].
func (t *poolTracer) TracePrepareStart(ctx context.Context, _ *pgx.Conn, _ pgx.TracePrepareStartData) context.Context {
	return ctx
}

// TracePrepareEnd implements [pgx.PrepareTracer].
func (t *poolTracer) TracePrepareEnd(_ context.Context, _ *pgx.Conn, _ pgx.TracePrepareEndData) {
}

type traceQuery struct {
	Begin time.Time
	Attrs []attribute.KeyValue
}

// TraceQueryStart implements [pgx.QueryTracer].
func (t *poolTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, queryKey, &traceQuery{
		Begin: time.Now(),
		Attrs: []attribute.KeyValue{
			semconv.DBStatement(data.SQL),
			pgpidAttr(conn),
		},
	})
}

// TraceQueryEnd implements [pgx.QueryTracer].
func (t *poolTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	q := ctx.Value(queryKey).(*traceQuery)
	op, affected := strings.TrimRight(data.CommandTag.String(), ` 0123456789`), data.CommandTag.RowsAffected()
	dur := time.Since(q.Begin)

	poolUseTime.Record(ctx, dur.Milliseconds(), metric.WithAttributeSet(t.metricAttrs))
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(append(q.Attrs, semconv.DBOperation(op), dbAffected.Int64(affected))...)
	ev := zlog.Debug(ctx).
		Str("operation", op).
		Int64("affected", affected).
		Stringer("duration", dur)
	err := data.Err
	span.RecordError(err)
	if err != nil {
		span.SetStatus(codes.Error, "query error")
		ev = ev.Err(err)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	// Don't bother logging any of the transaction commands.
	switch op {
	case "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE":
		ev.Discard().Send()
	default:
		ev.Msg("query done")
	}
}
