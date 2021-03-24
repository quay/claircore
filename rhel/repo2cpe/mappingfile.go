package repo2cpe

import (
	"context"

	"github.com/quay/zlog"
)

// MappingFile is a data struct for mapping file between repositories and CPEs
type MappingFile struct {
	Data map[string]Repo `json:"data"`
}

// Repo structure holds information about CPEs for given repo
type Repo struct {
	CPEs []string `json:"cpes"`
}

func (m *MappingFile) Get(ctx context.Context, rs []string) ([]string, error) {
	s := map[string]struct{}{}
	for _, r := range rs {
		cpes, ok := m.Data[r]
		if !ok {
			zlog.Debug(ctx).
				Str("repository", r).
				Msg("repository not present in a mapping file")
			continue
		}
		for _, cpe := range cpes.CPEs {
			s[cpe] = struct{}{}
		}
	}

	i, r := 0, make([]string, len(s))
	for k := range s {
		r[i] = k
		i++
	}
	return r, nil
}
