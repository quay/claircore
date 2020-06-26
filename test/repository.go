package test

import (
	"fmt"
	"strconv"

	"github.com/quay/claircore"
)

// GenUniqueRepositories creates an array of unique repositories. the array is guaranteed not to have
// any duplicately named repo fields.
func GenUniqueRepositories(n int, opts ...GenRepoOption) []*claircore.Repository {
	repos := []*claircore.Repository{}
	for i := 0; i < n; i++ {
		r := claircore.Repository{
			ID:   strconv.Itoa(i),
			Name: fmt.Sprintf("repository-%d", i),
			Key:  fmt.Sprintf("key-%d", i),
			URI:  fmt.Sprintf("uri-%d", i),
		}
		for _, f := range opts {
			f(&r)
		}
		repos = append(repos, &r)
	}
	return repos
}

type GenRepoOption func(*claircore.Repository)
