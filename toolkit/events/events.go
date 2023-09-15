// Package events is a small event logging system.
package events

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// Group is a grouping of log events going to a common Sink.
type Group struct {
	mu   sync.Mutex // Protects errs
	sink Sink
	name string
	errs []error
}

// NewGroup creates a new Group "name" writing to Sink "sink".
//
// The passed Context is only used for the duration of the NewGroup call.
func NewGroup(ctx context.Context, sink Sink, name string) (*Group, error) {
	if err := sink.StartGroup(ctx, name); err != nil {
		return nil, err
	}
	g := &Group{
		sink: sink,
		name: name,
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(g, func(g *Group) {
		panic(fmt.Sprintf("%s:%d: Group not finished", file, line))
	})
	return g, nil
}

// Finish signals to the underlying sink that this group is done and reports any
// errors accumulated by derived Log objects.
func (g *Group) Finish(ctx context.Context) error {
	runtime.SetFinalizer(g, nil)
	if err := g.sink.FinishGroup(ctx, g.name); err != nil {
		g.pushErr(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := errors.Join(g.errs...); err != nil {
		return fmt.Errorf("events: error(s) while emitting logs:\n%w", err)
	}
	return nil
}

func (g *Group) event(topic string, ev Event) {
	if err := g.sink.Event(g.name, topic, ev); err != nil {
		g.pushErr(err)
	}
}

func (g *Group) pushErr(err error) {
	g.mu.Lock()
	g.errs = append(g.errs, err)
	g.mu.Unlock()
}

// Log is the facade that "user" code should expect.
type Log interface {
	Printf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	// Finish should be called in a defer, right after FromContext.
	Finish()
}

type opaque struct{}

var ctxKey = (*opaque)(nil)

// WithGroup returns a Context with the provided Group embedded.
//
// Functions further down the call stack can derive Log interfaces with
// FromContext.
func WithGroup(ctx context.Context, g *Group) context.Context {
	return context.WithValue(ctx, ctxKey, g)
}

// FromContext returns a Log implementation grouping messages under the provided
// topic.
//
// The returned implementation may be all no-op methods, so callers should avoid
// logging "expensive" data.
func FromContext(ctx context.Context, topic string) Log {
	g := ctx.Value(ctxKey).(*Group)
	if g == nil {
		return noop{}
	}
	l := log{
		g:     g,
		topic: topic,
	}
	g.sink.Topic(topic)
	l.buf.Grow(4 * 1024) // Guess
	return &l
}

// Sink is the interface that event sinks must implement.
type Sink interface {
	// StartGroup is called when a new group is created. The Context should only
	// be used for the duration of the StartGroup call.
	StartGroup(ctx context.Context, group string) error
	// Topic notifies the Sink that a topic has been started. The same topic may
	// be passed multiple times.
	Topic(string)
	// Event is called once per event, some time between StartGroup and
	// FinishGroup.
	Event(group, topic string, ev Event) error
	// FinishGroup is called when the group is finished. The Context may be
	// canceled when this method is called.
	FinishGroup(ctx context.Context, group string) error
}

// Event is the event information delivered to a Sink.
type Event struct {
	_key    struct{}
	Message string
	Error   bool
}
