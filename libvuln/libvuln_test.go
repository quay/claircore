package libvuln

import (
	"bytes"
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func TestMatcherLog(t *testing.T) {
	const want = `{"matchers":[{"name":"test-matcher","docs":"https://pkg.go.dev/github.com/quay/claircore/libvuln"}]}` + "\n"
	var buf bytes.Buffer
	log := zerolog.New(&buf)
	log.Log().Array("matchers", matcherLog([]driver.Matcher{&TestMatcher{}})).Send()

	got := buf.String()
	t.Logf("got: %+#q", got)
	if got != want {
		t.Errorf("want: %+#q", want)
	}
}

// Helper for above test
type TestMatcher struct{}

var _ driver.Matcher = (*TestMatcher)(nil)

func (*TestMatcher) Name() string {
	return "test-matcher"
}

func (*TestMatcher) Filter(*claircore.IndexRecord) bool {
	return false
}

func (*TestMatcher) Query() []driver.MatchConstraint {
	return nil
}

func (*TestMatcher) Vulnerable(context.Context, *claircore.IndexRecord, *claircore.Vulnerability) (bool, error) {
	return false, nil
}
