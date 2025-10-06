package nodejs

import (
	"testing"

	"github.com/quay/claircore/test"
)

func TestMatcher(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	test.RunMatcherTests(ctx, t, "testdata/matcher", new(Matcher))
}
