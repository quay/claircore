package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/quay/claircore/libvuln"
	"log"
	"net/http"
	"os"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/pkg/ctxlock"
)

func main() {
	ctx := context.Background()

	pool, err := postgres.Connect(ctx, "user=claircore dbname=claircore host=localhost port=5434", "libindex-test")
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	indexerStore, err := postgres.InitPostgresIndexerStore(ctx, pool, true)
	if err != nil {
		log.Fatalf("failed to initialize indexer store: %v", err)
	}

	matcherStore, err := postgres.InitPostgresMatcherStore(ctx, pool, true)
	if err != nil {
		log.Fatalf("failed to initialize matcher store: %v", err)
	}

	ctxLocker, err := ctxlock.New(ctx, pool)
	if err != nil {
		log.Fatalf("failed to create context locker: %v", err)
	}
	defer ctxLocker.Close(ctx)

	log.Print("successfully setup database")

	indexerOpts := &libindex.Options{
		Store:      indexerStore,
		Locker:     ctxLocker,
		FetchArena: libindex.NewRemoteFetchArena(http.DefaultClient, os.TempDir()),
		// see definition for more configuration options
	}
	indexer, err := libindex.New(ctx, indexerOpts, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to create indexer: %v", err)
	}

	matcherOpts := &libvuln.Options{
		Store:                    matcherStore,
		Locker:                   ctxLocker,
		DisableBackgroundUpdates: true,
		Client:                   http.DefaultClient,
		// see definition for more configuration options
	}
	matcher, err := libvuln.New(ctx, matcherOpts)
	if err != nil {
		log.Fatalf("failed to create matcher: %v", err)
	}
	doneUpdating := make(chan struct{}, 1)
	go func() {
		if err := matcher.FetchUpdates(ctx); err != nil {
			log.Fatalf("failed to fetcher matcher updates")
			// TODO: cancel context
		}
		log.Print("done with vulnerability updates")
		doneUpdating <- struct{}{}
	}()

	log.Print("successfully setup claircore services")

	digest, err := claircore.ParseDigest("sha256:18e50e8f053968541f0efef7bbfa8d58d876f251acdb9afecb2c7c6cec409e2f")
	if err != nil {
		log.Fatalf("failed to create image digest: %v", err)
	}

	url := "https://quay.io/v2/coreos/etcd/manifests/sha256:18e50e8f053968541f0efef7bbfa8d58d876f251acdb9afecb2c7c6cec409e2f"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Fatalf("failed to construct valid HTTP request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("failed to http request to get image info: %v", err)
	}
	defer resp.Body.Close()

	var ociManifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ociManifest); err != nil {
		log.Fatalf("failed to decode response: %v", err)
	}

	var layers []*claircore.Layer
	for _, layer := range ociManifest.Layers {
		blobURI := fmt.Sprintf("https://quay.io/v2/coreos/etcd/blobs/%s", layer.Digest)
		hash, err := claircore.ParseDigest(layer.Digest)
		if err != nil {
			log.Fatalf("failed to parse digest from layer info: %v", err)
		}
		l := &claircore.Layer{
			Hash: hash,
			URI:  blobURI,
		}
		layers = append(layers, l)
	}

	m := &claircore.Manifest{
		Hash:   digest,
		Layers: layers,
	}

	log.Print("successfully gathered image info")

	ir, err := indexer.Index(ctx, m)
	if err != nil {
		log.Fatalf("failed to create index report: %v", err)
	}

	log.Print("waiting for vulnerability updates")
	<-doneUpdating
	vr, err := matcher.Scan(ctx, ir)
	if err != nil {
		log.Fatalf("failed to create index report: %v", err)
	}

	log.Print("successfully scanned. outputting results")

	marshaled, err := json.MarshalIndent(vr, "", "   ")
	if err != nil {
		log.Fatalf("marshaling error: %v", err)
	}
	fmt.Println(string(marshaled))
}
