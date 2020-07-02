package contentmanifest

import (
	"context"

	"github.com/rs/zerolog"
)

// RepoCPEUpdater provides interface for providing a mapping
// between repositories and CPEs
type RepoCPEUpdater interface {
	Update(context.Context) error
	Get(context.Context, []string) ([]string, error)
}

// RepoCPEMapping struct handles translation of repositories to CPEs
type RepoCPEMapping struct {
	RepoCPEUpdater
}

// RepositoryToCPE translates repositories into CPEs
func (mapping *RepoCPEMapping) RepositoryToCPE(ctx context.Context, repositories []string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner.Scan.ContentManifest").
		Logger()
	mapping.Update(ctx)
	cpes, err := mapping.Get(ctx, repositories)
	log.Debug().Strs("repositories", repositories).Strs("cpes", cpes).Msg("Translating repositories into CPEs")
	return cpes, err
}
