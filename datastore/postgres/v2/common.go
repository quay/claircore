package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/indexer"
)

// WithMigrations specifies the migrations should be run upon connection.
//
// Usable as an [IndexerOption] and a [MatcherOption].
var WithMigrations = migrationsOption{}

type migrationsOption struct{}

// IndexerConfig implements [IndexerOption].
func (migrationsOption) indexerConfig(cfg indexerConfig) indexerConfig {
	cfg.Migrations = true
	return cfg
}

// MatcherConfig implements [MatcherOption].
func (migrationsOption) matcherConfig(cfg matcherConfig) matcherConfig {
	cfg.Migrations = true
	return cfg
}

// WithMinimumMigration specifies a minimum migration version that the package
// expects a database to be at.
//
// This is checked after migrations have run, if requested.
// The value used is the maximum of this and relevant "MinimumMigration" value
// ([MinimumMatcherMigration], [MinimumIndexerMigration]).
//
// Usable as an [IndexerOption] and a [MatcherOption].
func WithMinimumMigration(v int) minimumMigration {
	return minimumMigration{v: v}
}

type minimumMigration struct {
	v int
}

// IndexerConfig implements [IndexerOption].
func (m minimumMigration) indexerConfig(cfg indexerConfig) indexerConfig {
	if m.v > cfg.MinMigration {
		cfg.MinMigration = m.v
	}
	return cfg
}

// MatcherConfig implements [MatcherOption].
func (m minimumMigration) matcherConfig(cfg matcherConfig) matcherConfig {
	if m.v > cfg.MinMigration {
		cfg.MinMigration = m.v
	}
	return cfg
}

var (
	_ IndexerOption = minimumMigration{}
	_ MatcherOption = minimumMigration{}
)

// Minimum acceptable migration versions for the indicated database.
const (
	MinimumMatcherMigration = 10
	MinimumIndexerMigration = 7
)

const appnameKey = `application_name`

// StoreCommon is the embeddable struct for common store functions.
//
// Database methods should make use of the method, tx, call, and acquire methods.
// Helper functions may want to use callfile method, but extra care must be
// taken with the manually-specified query path.
type storeCommon struct {
	pool         *pgxpool.Pool
	version      int
	registration metric.Registration
	prefix       string
	spanAttrs    attribute.Set
	metricAttrs  attribute.Set
}

// Close closes the connection pool and unregisters the associated metrics.
func (m *storeCommon) Close() error {
	// There might be ordering concerns here?
	m.pool.Close()
	return m.registration.Unregister()
}

func (m *storeCommon) init(ctx context.Context, cfg *pgxpool.Config, prefix string) (err error) {
	if _, ok := cfg.ConnConfig.RuntimeParams[appnameKey]; !ok {
		cfg.ConnConfig.RuntimeParams[appnameKey] = "clair-" + prefix
	}
	spanAttrs := []attribute.KeyValue{
		semconv.DBSystemPostgreSQL,
		semconv.DBUser(cfg.ConnConfig.User),
		semconv.DBName(cfg.ConnConfig.Database),
	}
	if filepath.IsAbs(cfg.ConnConfig.Host) {
		spanAttrs = append(spanAttrs, semconv.NetworkTransportUnix)
	} else {
		spanAttrs = append(spanAttrs,
			semconv.NetworkTransportTCP,
			semconv.ServerAddress(cfg.ConnConfig.Host), // This may be incorrect if specified as an IP.
		)
		if p := int(cfg.ConnConfig.Port); p != 5432 && p != 0 { // If not default:
			spanAttrs = append(spanAttrs, semconv.ServerPort(p))
		}
	}

	m.spanAttrs = attribute.NewSet(spanAttrs...)
	metricAttrs := []attribute.KeyValue{attribute.String(`pool.name`, cfg.ConnConfig.RuntimeParams[appnameKey])}
	m.metricAttrs = attribute.NewSet(metricAttrs...)
	m.prefix = prefix
	// NOTE(hank) Keep an eye on the opentelemetery "semconv" package to see when
	// the conventions are added.

	cfg.AfterConnect = connectRegisterTypes
	cfg.ConnConfig.Tracer = m.tracer()

	m.pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := m.pool.QueryRow(ctx, `SELECT current_setting('server_version_num')::int;`, pgx.QueryExecModeExec).Scan(&m.version); err != nil {
		m.pool.Close()
		return err
	}

	// Add metrics that cannot change during the lifetime of this pool.
	poolIdleMax.Add(ctx, int64(cfg.MaxConns), metric.WithAttributeSet(m.metricAttrs))
	poolIdleMin.Add(ctx, int64(cfg.MinConns), metric.WithAttributeSet(m.metricAttrs))
	poolMax.Add(ctx, int64(cfg.MaxConns), metric.WithAttributeSet(m.metricAttrs))
	usageUsed := attribute.NewSet(append(metricAttrs, attribute.String("state", "used"))...)
	usageIdle := attribute.NewSet(append(metricAttrs, attribute.String("state", "idle"))...)
	m.registration, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		s := m.pool.Stat()
		o.ObserveInt64(poolUsage, int64(s.AcquiredConns()), metric.WithAttributeSet(usageUsed))
		o.ObserveInt64(poolUsage, int64(s.IdleConns()), metric.WithAttributeSet(usageIdle))
		o.ObserveInt64(poolPending, s.EmptyAcquireCount(), metric.WithAttributeSet(m.metricAttrs))
		o.ObserveInt64(poolTimeout, s.CanceledAcquireCount(), metric.WithAttributeSet(m.metricAttrs))
		return nil
	},
		poolUsage,
		poolPending,
		poolTimeout,
	)
	if err != nil {
		m.pool.Close()
		return err
	}

	return nil
}

// HaveMerge reports if the connected PostgreSQL supports [MERGE].
//
// [MERGE]: https://www.postgresql.org/docs/current/sql-merge.html
func (m *storeCommon) haveMerge() bool {
	return m.version >= 15_00_00
}

func (m *storeCommon) checkRevision(ctx context.Context, table pgx.Identifier, min int) error {
	var rev int
	// NOTE(hank) Using a dynamically constructed query here should be fine
	// because:
	//
	//   - The input is not under user control.
	//   - The input is only a few strings.
	//   - The [pgx.Identifier] type has a sanitization method that's explicitly
	//     made for this purpose.
	q := fmt.Sprintf(`SELECT MAX(version) FROM %s;`, table.Sanitize())
	if err := m.pool.QueryRow(ctx, q).Scan(&rev); err != nil {
		return errors.Join(
			fmt.Errorf(`postgres: unable to determine migration version: %w`, err),
			m.Close(),
		)
	}
	if got, want := rev, min; got < want {
		return errors.Join(
			fmt.Errorf(`postgres: database needs migrations run (%d < %d)`, got, want),
			m.Close(),
		)
	}

	return nil
}

// CtxKey is a type for the [context.Context] keys used throughout this package.
type ctxKey struct{}

// MethodKey is used to pass the method name down via [context.Context.Value].
var methodKey = ctxKey{}

// SpanKey is a type for passing the span name in the [context.Context].
type spanKey struct{}

// SpanKey is used to pass the span name down via [context.Context.Value].
var spanName = spanKey{}

// Method is a helper for setting up all the observability and logging for an
// exported method.
//
// This should be called immediately inside of exported methods. The returned
// function must be called to clean up the tracing span.
func (m *storeCommon) method(ctx context.Context, err *error) (context.Context, func()) {
	pc, _, _, _ := runtime.Caller(1)
	n := runtime.FuncForPC(pc).Name()
	funcPath := strings.TrimPrefix(n, "github.com/quay/claircore/")
	i := strings.LastIndexByte(n, '.')
	if i == -1 {
		panic("name without dot: " + n)
	}
	funcName := n[i+1:]
	sn := strings.TrimPrefix(path.Base(n), "v2.")
	ctx = context.WithValue(ctx, spanName, sn)
	ctx = context.WithValue(ctx, methodKey, funcName)
	ctx = zlog.ContextWithValues(ctx, "component", funcPath)
	mAttr := attribute.String(`method`, funcName)
	attrs := attribute.NewSet(append(m.spanAttrs.ToSlice(), mAttr)...)
	ctx, span := tracer.Start(ctx, sn, trace.WithAttributes(mAttr), trace.WithSpanKind(trace.SpanKindInternal))
	zlog.Debug(ctx).Msg("start")
	begin := time.Now()
	return ctx, func() {
		methodCount.Add(ctx, 1, metric.WithAttributeSet(attrs))
		methodDuration.Record(ctx, time.Since(begin).Milliseconds(), metric.WithAttributeSet(attrs))
		ev := zlog.Debug(ctx)
		if *err != nil {
			*err = fmt.Errorf("postgres: %s: %w", funcName, *err)
			span.RecordError(*err)
			span.SetStatus(codes.Error, "method error")
			ev = ev.Err(*err)
		} else {
			span.SetStatus(codes.Ok, "")
		}
		ev.Msg("done")
		span.End()
	}
}

// TxFunc is the function signature for the inner call of the [*storeMetrics.tx]
// helper.
type txFunc func(ctx context.Context, tx pgx.Tx) error

// Tx is a helper for setting up all the observability and logging for a
// database transaction. It's intended to be used with [pgx.BeginTxFunc].
//
// This should be used for a transaction that will need run multiple different
// queries. The main difference between this method and [call] is that it does
// not load a query and set the relevant span attributes.
func (m *storeCommon) tx(ctx context.Context, name string, inner txFunc) func(pgx.Tx) error {
	sn := ctx.Value(spanName).(string)
	return func(tx pgx.Tx) error {
		ctx, span := tracer.Start(ctx, path.Join(sn, name), trace.WithAttributes(), trace.WithSpanKind(trace.SpanKindInternal))
		defer span.End()
		return inner(ctx, tx)
	}
}

// CallFunc is the function signature for the inner call of the
// [*storeMetrics.call] helper.
type callFunc func(ctx context.Context, tx pgx.Tx, query string) error

// Call is a helper for setting up all the observability and logging for a
// database query within a transaction. It's intended to be used with
// [pgx.BeginFunc].
//
// This should be used to run a single query. The "inner" function should only
// be issuing the query and scanning the results.
func (m *storeCommon) call(ctx context.Context, name string, inner callFunc) func(pgx.Tx) error {
	mn := ctx.Value(methodKey).(string)
	fn := fmt.Sprintf("%s_%s.sql", mn, name)
	return m.callfile(ctx, fn, name, inner)
}

func loadquery(path string) string {
	b, err := fs.ReadFile(queries, strings.ToLower(path))
	if err != nil {
		panic("programmer error: bad query name: " + err.Error())
	}
	return string(b)
}

// Callfile is a helper that does not guess the SQL file name.
//
// This is useful for helper functions that are called from multiple methods.
func (m *storeCommon) callfile(ctx context.Context, file, name string, inner callFunc) func(pgx.Tx) error {
	fn := path.Join("queries", m.prefix, strings.ToLower(file))
	q := loadquery(fn)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		semconv.DBSQLTable(queryMetadata.Table[fn]),
	)
	if op := queryMetadata.Op[fn]; op != "" {
		span.SetAttributes(semconv.DBOperation(op))
	}
	sn := ctx.Value(spanName).(string)
	return func(tx pgx.Tx) error {
		ctx, span := tracer.Start(ctx, path.Join(sn, name), trace.WithAttributes(), trace.WithSpanKind(trace.SpanKindClient))
		defer span.End()
		span.SetAttributes(pgpidAttr(tx.Conn()))
		err := inner(ctx, tx, q)
		span.RecordError(err)
		if err != nil {
			span.SetStatus(codes.Error, "call error")
		} else {
			span.SetStatus(codes.Ok, "")
		}
		return err
	}
}

// AcquireFunc is the function signature for the inner call of the
// [*storeCommon.acquire] helper.
type acquireFunc func(ctx context.Context, c *pgxpool.Conn, query string) error

// Acquire is a helper for setting up all the observability and logging for a
// query on a connection without a transaction. It's intended to be used with
// [*pgxpool.Pool.AcquireFunc].
//
// This should be used to run a single query. The "inner" function should only
// be issuing the query and scanning the results.
func (m *storeCommon) acquire(ctx context.Context, name string, inner acquireFunc) func(*pgxpool.Conn) error {
	mn := ctx.Value(methodKey).(string)
	fn := path.Join("queries", m.prefix, fmt.Sprintf("%s_%s.sql", mn, name))
	q := loadquery(fn)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		semconv.DBSQLTable(queryMetadata.Table[fn]),
	)
	if op := queryMetadata.Op[fn]; op != "" {
		span.SetAttributes(semconv.DBOperation(op))
	}
	sn := ctx.Value(spanName).(string)
	return func(c *pgxpool.Conn) error {
		ctx, span := tracer.Start(ctx, path.Join(sn, name), trace.WithAttributes(), trace.WithSpanKind(trace.SpanKindClient))
		defer span.End()
		span.SetAttributes(pgpidAttr(c.Conn()))
		err := inner(ctx, c, q)
		span.RecordError(err)
		if err != nil {
			span.SetStatus(codes.Error, "call error")
		} else {
			span.SetStatus(codes.Ok, "")
		}
		return err
	}
}

// Tracer returns an implementation of the various pgx "Trace" interfaces:
//
//   - [pgx.BatchTracer]
//   - [pgx.ConnectTracer]
//   - [pgx.CopyFromTracer]
//   - [pgx.PrepareTracer]
//   - [pgx.QueryTracer]
func (m *storeCommon) tracer() *poolTracer {
	// See metrics.go for the definition.
	return &poolTracer{
		metricAttrs: m.metricAttrs,
	}
}

var (
	txRO = pgx.TxOptions{AccessMode: pgx.ReadOnly}
	txRW = pgx.TxOptions{AccessMode: pgx.ReadWrite}
)

// RotateVersionedScanners handles the common task of turning "slice-of-structs"
// into "struct-of-slices" specifically for [VersionedScanner]s.
func rotateVersionedScanners(vs []indexer.VersionedScanner) (out rotatedVersionedScanners) {
	out.Name = make([]string, len(vs))
	out.Version = make([]string, len(vs))
	out.Kind = make([]string, len(vs))
	for i, s := range vs {
		out.Name[i] = s.Name()
		out.Version[i] = s.Version()
		out.Kind[i] = s.Kind()
	}
	return out
}

type rotatedVersionedScanners struct {
	Name    []string
	Version []string
	Kind    []string
}

type artifact interface {
	claircore.Distribution | claircore.File | claircore.Package | claircore.Repository
}

func rotateArtifacts[T any](in []T) []any {
	const (
		pointerTo = iota
		packageID
		versionKind
	)
	var (
		pkgPointer = reflect.TypeOf((*claircore.Package)(nil))
		version    = reflect.TypeOf(claircore.Version{})
	)

	var t T
	typ := reflect.TypeOf(any(t))
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var out []any
	var index []int
	var action []int
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if f.Name == "ID" {
			continue
		}
		var s any
		switch f.Type {
		case pkgPointer:
			action = append(action, packageID)
			s = any(make([]*string, len(in)))
		case version:
			action = append(action, versionKind)
			out = append(out, any(make([]*string, len(in))))
			index = append(index, i)
			fallthrough
		default:
			action = append(action, pointerTo)
			s = reflect.MakeSlice(reflect.SliceOf(reflect.PointerTo(f.Type)), len(in), len(in)).
				Interface()
		}
		out = append(out, s)
		index = append(index, i)
	}

	for n := range in {
		v := reflect.ValueOf(&in[n])
		for v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		for j, i := range index {
			out := reflect.ValueOf(out[j]).Index(n)
			f := v.Field(i)
			switch action[j] {
			case versionKind:
				out.Set(f.FieldByName("Kind").Addr())
			case packageID:
				if f.IsNil() {
					continue
				}
				out.Set(f.Elem().FieldByName("ID").Addr())
			case pointerTo:
				out.Set(f.Addr())
			}
		}
	}

	return out
}
