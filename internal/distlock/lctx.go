package distlock

import (
	"sync"
	"time"
)

var closedchan = make(chan struct{})
var emptyTime = time.Time{}

func init() {
	close(closedchan)
}

// lctx implements the ctx.Context
// interface.
//
// provides custom error information when ctx
// is canceled.
type lctx struct {
	sync.Mutex
	err  error
	done chan struct{}
	v    map[interface{}]interface{}
}

func (c *lctx) Deadline() (deadline time.Time, ok bool) {
	return emptyTime, false
}

func (c *lctx) Done() <-chan struct{} {
	c.Lock()
	d := c.done
	c.Unlock()
	return d
}

func (c *lctx) Err() error {
	c.Lock()
	e := c.err
	c.Unlock()
	return e
}

func (c *lctx) Value(key interface{}) interface{} {
	c.Lock()
	v, ok := c.v[key]
	c.Unlock()
	if !ok {
		return nil
	}
	return v
}

func (c *lctx) cancel(err error) {
	if err == nil {
		panic("context: internal error: missing cancel error")
	}
	c.Lock()
	if c.err != nil {
		c.Unlock()
		return // already canceled
	}
	c.err = err
	if c.done == nil {
		c.done = closedchan
	} else {
		close(c.done)
	}
	c.Unlock()
}
