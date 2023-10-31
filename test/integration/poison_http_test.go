package integration

import (
	"context"
	"net/http"
	"testing"
)

func TestPoison(t *testing.T) {
	ctx := context.Background()
	t.Run("Direct", func(t *testing.T) {
		p := poisonedTransport("TEST")
		_, err := p.DialContext(ctx, "tcp6", "::1")
		if err == nil {
			t.Errorf("expected error, got: %v", err)
		}
		t.Log(err)
	})

	t.Run("Client", func(t *testing.T) {
		c := &http.Client{
			Transport: poisonedTransport("TEST"),
		}
		_, err := c.Head("http://[::1]/")
		if err == nil {
			t.Errorf("expected error, got: %v", err)
		}
		t.Log(err)
	})
}
