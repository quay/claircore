package aws

import (
	"fmt"
	"io"

	"github.com/quay/alas"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as a claircore.Updater
type Updater struct {
	release Releases
}

func NewUpdater(release Releases) (*Updater, error) {
	return &Updater{
		release: release,
	}, nil
}

func (u *Updater) Name() string {
	panic("not implemented")
}

func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	client, err := NewClient(u.release)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create client: %v", err)
	}

	repoMD, err := client.RepoMD()
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve repo metadata: %v", err)
	}

	updatesRepoMD, err := repoMD.Repo(alas.UpdateInfo, "")
	if err != nil {
		return nil, "", fmt.Errorf("updates repo metadata could not be retrieved: %v", err)
	}

	resp, err := client.Updates()
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve update info: %v", err)
	}

	return resp.Body, updatesRepoMD.Checksum.Sum, nil
}

func (u *Updater) Parse(contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	panic("not implemented")
}
