package fetcher

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/moby"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// fetcher is a private struct which implements our in memory scanner.Fetcher
type fetcher struct {
	// whether the fetcher is configured to download layer contents the layer's inmemory byte array
	// or to the system's disk
	fetchOpt scanner.LayerFetchOpt
	wc       *http.Client
	// a wrapped interface exposing the archive package in the moby project
	archiver moby.Archiver
	// lock to protect tmp file array
	fLock sync.Mutex
	// a temporary file where the layer's contents are stored
	tmp []*os.File
	// a logger with context.
	logger zerolog.Logger
}

// NewFetcher creates a new scanner.Fetcher which downloads
// layers to in memory byte arrays. if client and/or archiver is nil a default will be created.
// Fetcher is safe to share concurrently.
func New(client *http.Client, archiver moby.Archiver, fetchOpt scanner.LayerFetchOpt) *fetcher {
	if client == nil {
		client = &http.Client{}
	}
	if archiver == nil {
		archiver = moby.NewArchiver()
	}

	return &fetcher{
		fetchOpt: fetchOpt,
		wc:       client,
		archiver: archiver,
		logger:   log.With().Str("component", "fetcher").Logger(),
	}
}

// Fetch retrieves a layer from the provided claircore.Layer.RemotePath field,
// decompresses the archive if compressed, and copies the the http body
// either to an in memory layer.Bytes field or popultes layer.LocalPath with
// a local file system path to the archive.
func (f *fetcher) Fetch(ctx context.Context, layers []*claircore.Layer) error {
	var g errgroup.Group
	for _, l := range layers {
		ll := l
		g.Go(func() error {
			err := f.fetch(ctx, ll)
			return err
		})
	}
	// wait for any concurrent fetches to finish
	if err := g.Wait(); err != nil {
		return fmt.Errorf("encountered error while fetching a layer: %v", err)
	}
	return nil
}

// fetch is designed to be ran as a go routine. performs the logic for for
// fetching an individual layer's contents.
func (f *fetcher) fetch(ctx context.Context, layer *claircore.Layer) error {

	// it is valid and not perform a fetch.
	if layer.LocalPath != "" {
		return nil
	}

	// if no RemotePath was provided return error
	if layer.RemotePath.URI == "" {
		return fmt.Errorf("could not determine remove URI for layer %v. layer provided %v", layer.Hash, layer.RemotePath.URI)
	}

	// parse uri
	url, err := url.ParseRequestURI(layer.RemotePath.URI)
	if err != nil {
		return fmt.Errorf("failied to parse remote path uri: %v", err)
	}

	contents, err := f.fetchAndDecompress(ctx, url, layer.RemotePath.Headers)
	defer contents.Close()

	if err != nil {
		return fmt.Errorf("failed to fetch and decompress contents of layer %s", layer.Hash)
	}

	switch f.fetchOpt {
	case scanner.InMem:
		err = f.inMem(ctx, contents, layer)
		if err != nil {
			return fmt.Errorf("failed to write layer contents to in memory buffer: %v", err)
		}
	case scanner.OnDisk:
		fd, err := f.onDisk(ctx, contents, layer)
		if err != nil {
			return fmt.Errorf("failed to write layer contents to tmp file: %v", err)
		}
		f.addTemp(fd)
	case scanner.Tee:
		fd, err := f.tee(ctx, contents, layer)
		if err != nil {
			return fmt.Errorf("failed to tee layer contents to disk and in memory buffer: %v", err)
		}
		f.addTemp(fd)
	default:
		return fmt.Errorf("invalid or unimplemented fetch options provide")
	}

	return nil
}

// fetchandDecompress attempts to retrieve the layer contents at the given URI. If a successful http call can be made we decompress
// the contents and return an io.ReadCloser where the decompressed contents maybe read.
func (f *fetcher) fetchAndDecompress(ctx context.Context, url *url.URL, headers map[string][]string) (io.ReadCloser, error) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    url,
		Header: headers,
	}
	req = req.WithContext(ctx)
	resp, err := f.wc.Do(req)
	// defer resp.Body.Close()

	rc, err := f.archiver.DecompressStream(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress contents at %v: %v", url.String(), err)
	}

	return rc, nil
}

// tee will both read the contents of the io.ReaderCloser returned from fetchAndDecompress to both
// the layer's in memory byte array and a temporary file on disk
func (f *fetcher) tee(ctx context.Context, contents io.ReadCloser, layer *claircore.Layer) (*os.File, error) {
	// tee will write both to memory and onto disk

	// create tmp fd for reading into
	fd, err := ioutil.TempFile("", layer.Hash)
	if err != nil {
		return nil, fmt.Errorf("defaultFetcher: unable to create temp file for archive contents")
	}
	defer fd.Close()
	bufferedFD := bufio.NewWriter(fd)

	// create buffer we read into also
	b := bytes.NewBuffer([]byte{})

	// create multiwriter with byte buffer and fd being the targets
	mw := io.MultiWriter(bufferedFD, b)

	// copy contents into multiwriter
	_, err = io.Copy(mw, contents)
	if err != nil {
		return nil, fmt.Errorf("defaultFetcher: unable to tee output to buffer and file: %v", err)
	}

	// set LocalPath on layer
	layer.LocalPath = fd.Name()
	// set Bytes on layer
	layer.Bytes = b.Bytes()

	return fd, nil
}

// tee will both read the contents of the io.ReaderCloser returned from fetchAndDecompress to both
// the layer's in memory byte array and a temporary file on disk
func (f *fetcher) onDisk(ctx context.Context, contents io.ReadCloser, layer *claircore.Layer) (*os.File, error) {
	// create tmp fd
	fd, err := ioutil.TempFile("", layer.Hash)
	if err != nil {
		return nil, fmt.Errorf("defaultFetcher: unable to create temp file for archive contents")
	}
	defer fd.Close()
	bufferedFD := bufio.NewWriter(fd)

	// write tar to temp file
	_, err = io.Copy(bufferedFD, contents)
	if err != nil {
		return nil, fmt.Errorf("defaultFetcher: failed to copy decompressed archive to fd %v: %v", fd.Name(), err)
	}

	// set LocalPath on layer
	layer.LocalPath = fd.Name()

	return fd, nil
}

func (f *fetcher) inMem(ctx context.Context, contents io.ReadCloser, layer *claircore.Layer) error {
	b, err := ioutil.ReadAll(contents)
	if err != nil {
		return fmt.Errorf("failed to copy uncompressed tar into byte array: %v", err)
	}

	layer.Bytes = b
	return nil
}

// Purge will remove the tmp fiile created if the fetcher was configured
// to download layer contents to disk. Calling this method otherwise is a no-op
// and is safe.
func (f *fetcher) Purge() {
	f.fLock.Lock()
	if f.tmp != nil {
		for _, fd := range f.tmp {
			err := os.Remove(fd.Name())
			if err != nil {
				f.logger.Error().Msgf("defaultFetcher: failed to delete tmp file %v: %v", fd.Name(), err)
			}
		}
	}
	f.fLock.Unlock()
}

func (f *fetcher) addTemp(fd *os.File) {
	f.fLock.Lock()
	f.tmp = append(f.tmp, fd)
	f.fLock.Unlock()
}
