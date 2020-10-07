package repo2cpe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

const (
	updateInterval = 10 * time.Minute
)

// LocalUpdaterJob provides local repo -> cpe mapping
// via a continually updated local mapping file
type LocalUpdaterJob struct {
	URL    string
	Client *http.Client
	// an atomic value holding the latest
	// parsed MappingFile
	mapping      atomic.Value
	lastModified string
}

// NewLocalUpdaterJob returns a unstarted UpdaterJob.
func NewLocalUpdaterJob(url string, client *http.Client) *LocalUpdaterJob {
	if client == nil {
		client = http.DefaultClient
	}
	return &LocalUpdaterJob{
		URL:    url,
		Client: client,
	}
}

// Get translates repositories into CPEs using a mapping file.
//
// Get is safe for concurrent usage.
func (updater *LocalUpdaterJob) Get(ctx context.Context, repositories []string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/repo2cpe/updater/LocalUpdaterJob.Get").
		Logger()
	if len(repositories) == 0 {
		return []string{}, nil
	}

	cpes := []string{}
	var mapping *MappingFile = updater.mapping.Load().(*MappingFile)
	if mapping == nil {
		// mapping not set yet. not an error
		return cpes, nil
	}

	for _, repo := range repositories {
		if repoCPEs, ok := mapping.Data[repo]; ok {
			for _, cpe := range repoCPEs.CPEs {
				cpes = appendUnique(cpes, cpe)
			}
		} else {
			log.Debug().Str("repository", repo).Msg("The repository is not present in a mapping file")
		}
	}
	return cpes, nil
}

// Start begins a local updater job keeping the atomic mapping variable
// up to date.
//
// Start will block until the first atomic update of the mapping file completes.
//
// All subsequent updates are performed asynchronously in a goroutine.
//
// Canceling the ctx will cancel the updating.
func (updater *LocalUpdaterJob) Start(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/repo2cpe/updater/LocalUpdaterJob.Start").
		Logger()
	err := updater.do(ctx)
	if err != nil {
		log.Error().Err(err).Msg("received error updating mapping file")
	}

	go func() {
		t := time.NewTicker(updateInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				log.Debug().Msg("updater tick")
				err := updater.do(ctx)
				if err != nil {
					log.Error().Err(err).Msg("received error updating mapping file")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

// do is an internal method called to perform an atomic update
// of the mapping file.
//
// this method will not be ran concurrently.
func (updater *LocalUpdaterJob) do(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/repo2cpe/updater/LocalUpdaterJob.do").
		Str("url", updater.URL).
		Logger()
	log.Debug().Msg("attempting fetch of repo2cpe mapping file")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updater.URL, nil)
	if err != nil {
		return err
	}
	if updater.lastModified != "" {
		req.Header.Set("if-modified-since", updater.lastModified)
	}

	resp, err := updater.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		log.Debug().
			Str("since", updater.lastModified).
			Msg("response not modified. no update necessary")
		return nil
	default:
		return fmt.Errorf("received status code %q querying mapping url", resp.StatusCode)
	}

	var mapping *MappingFile
	err = json.NewDecoder(resp.Body).Decode(&mapping)
	if err != nil {
		return fmt.Errorf("failed to decode mapping file: %v", err)
	}

	updater.lastModified = resp.Header.Get("last-modified")
	// atomic store of mapping file
	updater.mapping.Store(mapping)
	log.Debug().Msg("atomic update of local mapping file complete")
	return nil
}

func appendUnique(items []string, item string) []string {
	for _, value := range items {
		if value == item {
			return items
		}
	}
	items = append(items, item)
	return items
}
