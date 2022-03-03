package events

import (
	"context"
	"errors"
	"io"
	"testing"
)

type testSink struct{ *testing.T }

var _ Sink = (*testSink)(nil)

func (s *testSink) StartGroup(ctx context.Context, group string) error {
	s.Logf("group start: %s", group)
	return nil
}

func (s *testSink) Topic(t string) {
	s.Logf("topic: %s", t)
}

func (s *testSink) Event(group, topic string, ev Event) error {
	s.Logf("%s/%s: err?%v %s", group, topic, ev.Error, ev.Message)
	return nil
}

func (s *testSink) FinishGroup(ctx context.Context, group string) error {
	s.Logf("group finish: %s", group)
	return nil
}

func TestLog(t *testing.T) {
	ctx := context.Background()
	sink := &testSink{T: t}
	g, err := NewGroup(ctx, sink, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := g.Finish(ctx); err != nil {
			t.Error(err)
		}
	}()

	ctx = WithGroup(ctx, g)
	l := FromContext(ctx, "topic")
	defer l.Finish()
	l.Printf("")
	l.Errorf("")
	for i := 0; i < 10; i++ {
		l.Printf("hello, %d", i)
		l.Errorf("hello, %d", i)
	}
}

type errSink struct {
	start  error
	event  error
	finish error
}

var _ Sink = (*errSink)(nil)

func (s *errSink) StartGroup(ctx context.Context, group string) (err error) {
	err, s.start = s.start, nil
	return err
}

func (s *errSink) Topic(t string) {}

func (s *errSink) Event(group, topic string, ev Event) (err error) {
	err, s.event = s.event, nil
	return err
}

func (s *errSink) FinishGroup(ctx context.Context, group string) (err error) {
	err, s.finish = s.finish, nil
	return err
}

func TestLogError(t *testing.T) {
	startErr := errors.New("start")
	eventErr := errors.New("event")
	finishErr := errors.New("finish")
	ctx := context.Background()
	sink := &errSink{
		start:  startErr,
		event:  eventErr,
		finish: finishErr,
	}
	_, err := NewGroup(ctx, sink, t.Name())
	if !errors.Is(err, startErr) {
		t.Errorf("got: %v, want: %v", err, startErr)
	}
	g, err := NewGroup(ctx, sink, t.Name())
	if err != nil {
		t.Fatal(err)
	}

	ctx = WithGroup(ctx, g)
	l := FromContext(ctx, "topic")
	l.Printf("hello, test")
	l.Finish()

	err = g.Finish(ctx)
	if got, want := err, eventErr; !errors.Is(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
	if got, want := err, finishErr; !errors.Is(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
	if got, want := err, io.EOF; errors.Is(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
	t.Log(err)
}
