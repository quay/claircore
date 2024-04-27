// Package plugin is the "user" half of the "toolkit/registry" package.
//
// This package implements a uniform construction and pooling workflow for any
// type of object. The only restriction is that the type must have runtime
// reflection information. This means that types defined in "_test" files will
// not work; use a "normal" package that's only imported by test files to work
// around this.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"runtime/pprof"
	"sync"

	"github.com/jackc/puddle/v2"
	"github.com/quay/claircore/toolkit/registry"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Pool is a typesafe allocation pool for named resources.
type Pool[T any] struct {
	mu    sync.RWMutex
	pool  map[string]*puddle.Pool[T]
	close map[string]metric.Registration
}

// Getpool returns the named pool.
func (p *Pool[T]) getpool(_ context.Context, name string) (*puddle.Pool[T], error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	np, ok := p.pool[name]
	if !ok {
		return nil, fmt.Errorf("plugin: no such plugin: %q", name)
	}
	return np, nil
}

// Get returns a constructed instance of the given type parameter or blocks
// until one is available.
//
// If an error is not reported by this function, the returned cleanup function
// must be called or a pool slot will be leaked.
func (p *Pool[T]) Get(ctx context.Context, name string) (T, func(), error) {
	pool, err := p.getpool(ctx, name)
	if err != nil {
		var t T
		return t, nil, err
	}
	res, err := pool.Acquire(ctx)
	if err != nil {
		var t T
		return t, nil, fmt.Errorf("plugin: error acquiring plugin %q: %w", name, err)
	}
	return res.Value(), res.Release, nil
}

// GetAll returns one instance of every named plugin in the pool.
//
// This is only useful for "entrypoint" plugins, i.e. plugins that report
// additional names and/or register other plugins.
func (p *Pool[T]) GetAll(ctx context.Context) ([]T, func(), error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]T, 0, len(p.pool))
	funcs := make([]func(), 0, len(p.pool))
	for _, np := range p.pool {
		res, err := np.Acquire(ctx)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, res.Value())
		funcs = append(funcs, res.Release)
	}
	done := func() {
		for _, f := range funcs {
			f()
		}
	}
	return out, done, nil
}

// Close prevents new objects from being handed out, then closes all named
// pools, waiting until all currently leased objects are returned.
//
// Calling Close twice may panic the goroutine.
// Not calling Close may panic the program.
func (p *Pool[T]) Close() {
	p.mu.Lock()
	// Leak the write lock
	for n, tp := range p.pool {
		tp.Close()
		delete(p.pool, n)
	}
	for n, reg := range p.close {
		reg.Unregister()
		delete(p.close, n)
	}
	runtime.SetFinalizer(p, nil)
}

// Config is the uniform configuration struct for objects constructed by Pools.
//
// The Config struct is untyped, so all plugins can use the same instance,
// assuming there are no name conflicts. If using valid Claircore names, this
// should be impossible.
type Config struct {
	// Configs maps name to a JSON serialized representation of the
	// configuration for that plugin.
	//
	// The JSON document will be schema-checked at Pool construction.
	// Modifying the keys or values of this map may panic the program.
	Configs map[string][]byte
	// PoolSize controls the number of objects that will be pooled. This should
	// be sized for the number of expected concurrent requests.
	PoolSize int
	// HTTPClient is an HTTP client that can be used by plugins that need it.
	//
	// This member should always be provided even if Internet access is
	// disallowed. Connections can be controlled lower in the stack.
	HTTPClient *http.Client
	// Dialer is a net.Dialer that can be used by plugins that need it.
	//
	// This member should always be provided even if Internet access is
	// disallowed. Connections can be controlled by the control functions here.
	// It it not assumed that the HTTPClient member uses this net.Dialer.
	Dialer *net.Dialer
}

// EmptyObject is the "zero value" returned by [Config.Get].
var emptyObject = []byte(`null`)

// Get returns the named configuration, or a zero value if not present.
func (p *Config) Get(name string) []byte {
	v, ok := p.Configs[name]
	if !ok {
		return emptyObject
	}
	return v
}

// NewPool constructs a Pool for the named plugins of the given type.
//
// The configuration schema is checked once at construction.
// It is an error to provide names that are not registered in global registry.
func NewPool[T any](ctx context.Context, cfg *Config, names ...string) (*Pool[T], error) {
	ctx, span := tracer.Start(ctx, "NewPool")
	defer span.End()
	descs, err := registry.GetDescription[T](names...)
	if err != nil {
		return nil, fmt.Errorf("plugin: unable to get Descriptions: %w", err)
	}

	pool := Pool[T]{
		pool:  make(map[string]*puddle.Pool[T], len(names)),
		close: make(map[string]metric.Registration),
	}
	c := NewCompiler(descs)

	for name, desc := range descs {
		schema, err := c.Compile(name)
		if err != nil {
			return nil, fmt.Errorf("plugin: schema compilation failed for %q: %w", name, err)
		}
		printDoc(ctx, name, schema.Description)

		cfgdata := cfg.Get(name)
		var val any
		if err := json.Unmarshal(cfgdata, &val); err != nil {
			return nil, fmt.Errorf("plugin: unable to unmarshal configuration for %q: %w", name, err)
		}
		if err := schema.Validate(val); err != nil {
			return nil, fmt.Errorf("plugin: schema validation failed for %q: %w", name, err)
		}

		np, err := puddle.NewPool(configFor(ctx, cfg, name, desc))
		if err != nil {
			return nil, fmt.Errorf("plugin: unable to create pool: %w", err)
		}
		if err := np.CreateResource(ctx); err != nil {
			return nil, fmt.Errorf("plugin: unable to construct resource: %w", err)
		}
		pool.pool[name] = np
		pool.metricsSetup(name, np) // See metrics.go
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&pool, func(p *Pool[T]) {
		panic(fmt.Sprintf("%s:%d: Pool[T] not closed", file, line))
	})
	return &pool, nil
}

// ConfigFor builds the puddle config for the given name and Description.
//
// This function ensures that constructors and destructors are used uniformly.
func configFor[T any](ctx context.Context, cfg *Config, name string, desc *registry.Description[T]) *puddle.Config[T] {
	labels := pprof.Labels("plugin.name", name)
	b := cfg.Get(name)
	attr := attribute.String("plugin.name", name)
	constructor := func(ctx context.Context) (res T, err error) {
		ctx, span := tracer.Start(ctx, "Pool.constructor")
		defer span.End()
		span.SetAttributes(attr)
		var called bool
		dec := func(v any) error {
			called = true
			return json.Unmarshal(b, v)
		}
		pprof.Do(ctx, labels, func(ctx context.Context) {
			res, err = desc.New(ctx, dec)
		})
		if err != nil {
			return res, err
		}
		if !called {
			return res, fmt.Errorf("plugin: constructor for %q did not call the configuration hook", name)
		}
		// Could turn this into a loop with some use of reflect, if we want to
		// use reflect in the constructor.
		var v any = res
		if v, ok := v.(registry.CanHTTP); ok {
			span.AddEvent("can HTTP")
			pprof.Do(ctx, labels, func(ctx context.Context) {
				err = v.HTTPClient(ctx, cfg.HTTPClient)
			})
			if err != nil {
				return res, err
			}
		}
		if v, ok := v.(registry.CanDial); ok {
			span.AddEvent("can Dial")
			pprof.Do(ctx, labels, func(ctx context.Context) {
				err = v.NetDialer(ctx, cfg.Dialer)
			})
			if err != nil {
				return res, err
			}
		}

		return res, nil
	}
	destructor := func(res T) {
		var err error
		// This isn't an if-chain like in the constructor closure because the
		// methods all share a name, so only one can be implemented.
		switch f := any(res).(type) {
		case Closer:
			pprof.Do(ctx, labels, func(ctx context.Context) {
				err = f.Close()
			})
		case ContextErrCloser:
			pprof.Do(ctx, labels, func(ctx context.Context) {
				err = f.Close(ctx)
			})
		case ContextCloser:
			pprof.Do(ctx, labels, f.Close)
		default:
		}
		if err != nil {
			zlog.Warn(ctx).
				Str("plugin", name).
				Err(err).
				Msg("error in plugin destructor")
		}
	}
	return &puddle.Config[T]{
		Constructor: constructor,
		Destructor:  destructor,
		MaxSize:     int32(cfg.PoolSize),
	}
}

type (
	// Closer is the standard io.Closer.
	// Used in the Pool's destructor if implemented by the concrete type.
	Closer = io.Closer
	// ContextCloser is a Close method that takes a context. The [Context]
	// argument may be from an unrelated background context.
	// Used in the Pool's destructor if implemented by the concrete type.
	ContextCloser interface {
		Close(context.Context)
	}
	// ContextErrCloser is a Close method that takes a context and returns an
	// error. The [Context] argument may be from an unrelated background
	// context.
	// Used in the Pool's destructor if implemented by the concrete type.
	ContextErrCloser interface {
		Close(context.Context) error
	}
)
