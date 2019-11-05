package test

import (
	"fmt"

	"github.com/quay/claircore"
)

// GenUniqueRepositories creates an array of unique repositories. the array is guaranteed not to have
// any duplicately named repo fields.
func GenUniqueRepositories(n int) []*claircore.Repository {
	repos := []*claircore.Repository{}
	for i := 0; i < n; i++ {
		repos = append(repos, &claircore.Repository{
			ID:   i,
			Name: fmt.Sprintf("distribution-%d", i),
			Key:  fmt.Sprintf("key-%d", i),
			URI:  fmt.Sprintf("uri-%d", i),
		})
	}
	return repos
}
