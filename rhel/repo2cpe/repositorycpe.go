package repo2cpe

import (
	"context"
)

// RepoCPEUpdater provides interface for providing a mapping
// between repositories and CPEs
type RepoCPEUpdater interface {
	Get(context.Context, []string) ([]string, error)
}

// RepoCPEMapping struct handles translation of repositories to CPEs
type RepoCPEMapping struct {
	RepoCPEUpdater
}

// RepositoryToCPE translates repositories into CPEs
func (mapping *RepoCPEMapping) RepositoryToCPE(ctx context.Context, repositories []string) ([]string, error) {
	cpes, err := mapping.Get(ctx, repositories)
	return cpes, err
}
