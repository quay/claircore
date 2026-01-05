package events

import (
	"context"
	"errors"
	"fmt"
)

// Group is a grouping of log events going to a common Sink.
//
// Deprecated: This was never used.
type Group struct{}

// NewGroup creates a new Group "name" writing to Sink "sink".
//
// The passed Context is only used for the duration of the NewGroup call.
//
// Deprecated: This was never used.
func NewGroup(_ context.Context, _ Sink, _ string) (*Group, error) {
	return nil, fmt.Errorf(`events.Group API: NewGroup: %w`, errors.ErrUnsupported)
}

// Finish signals to the underlying sink that this group is done and reports any
// errors accumulated by derived Log objects.
//
// Deprecated: This was never used.
func (g *Group) Finish(_ context.Context) error {
	return fmt.Errorf(`events.Group API: Group.Finish: %w`, errors.ErrUnsupported)
}

// Log is the facade that "user" code should expect.
//
// Deprecated: This was never used.
type Log interface {
	Printf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	// Finish should be called in a defer, right after FromContext.
	Finish()
}

// WithGroup returns a Context with the provided Group embedded.
//
// Functions further down the call stack can derive Log interfaces with
// FromContext.
//
// Deprecated: This was never used, and will not return a child
// [context.Context].
func WithGroup(ctx context.Context, _ *Group) context.Context {
	return ctx
}

// FromContext returns a Log implementation grouping messages under the provided
// topic.
//
// The returned implementation may be all no-op methods, so callers should avoid
// logging "expensive" data.
//
// Deprecated: This was never used, and will return a no-op implementation.
func FromContext(_ context.Context, _ string) Log {
	return noop{}
}

// Noop is an implementer of Log that does nothing.
type noop struct{}

func (noop) Printf(_ string, _ ...interface{}) {}
func (noop) Errorf(_ string, _ ...interface{}) {}
func (noop) Finish()                           {}

// Sink is the interface that event sinks must implement.
//
// Deprecated: This was never used.
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
//
// Deprecated: This was never used.
type Event struct {
	_key    struct{}
	Message string
	Error   bool
}
