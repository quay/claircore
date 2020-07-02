package contentmanifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type LocalFileMetadata struct {
	lastUpdateDate   time.Time
	lastHeaderQuery  time.Time
	mappingFileMutex sync.Mutex
	updaterMutex     sync.Mutex
}

// LocalUpdaterJob periodically updates mapping file and store it in local storage
type LocalUpdaterJob struct {
	LocalPath string
	URL       string
	Client    *http.Client
}

var fileMetadata = make(map[string]*LocalFileMetadata)

// NewLocalUpdaterJob creates new LocalUpdaterJob
func NewLocalUpdaterJob(localPath string, url string, client *http.Client) *LocalUpdaterJob {
	updater := LocalUpdaterJob{
		LocalPath: localPath,
		URL:       url,
		Client:    client,
	}
	if _, ok := fileMetadata[localPath]; !ok {
		fileMetadata[localPath] = &LocalFileMetadata{}
	}
	return &updater
}

// Get translate repositories into CPEs using a mapping file
func (updater *LocalUpdaterJob) Get(ctx context.Context, repositories []string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner.Scan.LocalUpdaterJob").
		Logger()
	if len(repositories) == 0 {
		return []string{}, nil
	}
	fileMetadata[updater.LocalPath].mappingFileMutex.Lock()
	defer fileMetadata[updater.LocalPath].mappingFileMutex.Unlock()
	f, err := os.Open(updater.LocalPath)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	mappingContent := MappingFile{}
	err = json.NewDecoder(f).Decode(&mappingContent)
	if err != nil {
		return []string{}, err
	}
	cpes := []string{}
	for _, repo := range repositories {
		if repoCPEs, ok := mappingContent.Data[repo]; ok {
			for _, cpe := range repoCPEs.CPEs {
				cpes = appendUnique(cpes, cpe)
			}
		} else {
			log.Debug().Str("repository", repo).Msg("The repository is not present in a mapping file")
		}
	}
	return cpes, nil
}

// Update fetches mapping file using HTTP and store it locally in regular intervals
func (updater *LocalUpdaterJob) Update(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner.Scan.LocalUpdaterJob").
		Logger()
	fileMetadata[updater.LocalPath].updaterMutex.Lock()
	defer fileMetadata[updater.LocalPath].updaterMutex.Unlock()
	if updater.shouldBeUpdated(ctx, &log) {
		log.Info().Msg("The repo2cpe mapping has newer version. Updating...")
		data, lastModified, err := updater.fetch(ctx, &log)
		if err != nil {
			return err
		}
		err = updater.store(data)
		if err != nil {
			return err
		}
		log.Info().Str("path", updater.LocalPath).Msg("Repo-CPE mapping file has been successfully updated")
		if lastModified != "" {
			lastModifiedDate, err := time.Parse(time.RFC1123, lastModified)
			if err != nil {
				log.Err(err).Str("lastUpdateDate", fileMetadata[updater.LocalPath].lastUpdateDate.String()).Msg("Failed to parse lastUpdateDate")
				return err
			}
			// update local timestamp with latest date
			fileMetadata[updater.LocalPath].lastUpdateDate = lastModifiedDate
		}
	}
	return nil
}

func (updater *LocalUpdaterJob) shouldBeUpdated(ctx context.Context, log *zerolog.Logger) bool {
	if time.Now().Add(-8 * time.Hour).Before(fileMetadata[updater.LocalPath].lastUpdateDate) {
		// mapping has been updated in past 8 hours
		// no need to query file headers
		return false
	}
	// if it is more than 10 hours let's check file last-modified every 15 minutes
	if time.Now().Add(-15 * time.Minute).Before(fileMetadata[updater.LocalPath].lastHeaderQuery) {
		// last header query has been done less than 15 minutes ago
		return false
	}
	log.Debug().Msg("The repo2cpe hasn't been updated in past 8 hours.")
	// mapping file was updated more then 8 hours ago..
	// Let's check whether header has changed
	log.Debug().Str("url", updater.URL).Msg("Fetching repo2cpe last-modified")
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, updater.URL, nil)
	if err != nil {
		return true
	}

	resp, err := updater.Client.Do(req)
	if err != nil {
		return true
	}
	if resp.StatusCode != http.StatusOK {
		log.Warn().
			Int("code", resp.StatusCode).
			Str("url", updater.URL).
			Str("method", "HEAD").
			Msg("Got non 2xx code from repo2cpe mapping")
		return true
	}
	lastModified := resp.Header.Get("last-modified")
	lastModifiedTime, err := time.Parse(time.RFC1123, lastModified)
	if err != nil {
		return true
	}
	fileMetadata[updater.LocalPath].lastHeaderQuery = time.Now()
	return lastModifiedTime.After(fileMetadata[updater.LocalPath].lastUpdateDate)
}

func (updater *LocalUpdaterJob) fetch(ctx context.Context, log *zerolog.Logger) ([]byte, string, error) {
	log.Info().Str("url", updater.URL).Msg("Fetching repo2cpe mapping file")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updater.URL, nil)
	if err != nil {
		return []byte{}, "", err
	}

	resp, err := updater.Client.Do(req)
	if err != nil {
		return []byte{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Warn().
			Int("code", resp.StatusCode).
			Str("url", updater.URL).
			Str("method", "GET").
			Msg("Got non 2xx code from repo2cpe mapping")
		return []byte{}, "", fmt.Errorf("Got non 2xx code from repo2cpe mapping: [GET] %d - %s", resp.StatusCode, updater.URL)
	}
	lastModified := resp.Header.Get("last-modified")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, "", err
	}
	return body, lastModified, nil
}

func (updater *LocalUpdaterJob) store(data []byte) error {
	fileMetadata[updater.LocalPath].mappingFileMutex.Lock()
	defer fileMetadata[updater.LocalPath].mappingFileMutex.Unlock()
	f, err := os.OpenFile(updater.LocalPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		return err
	}
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
