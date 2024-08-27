package nodejs

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/test"
)

func TestMatcher(t *testing.T) {
	t.Parallel()
	test.RunMatcherTests(zlog.Test(context.Background(), t), t, "testdata/matcher", new(Matcher))
}
