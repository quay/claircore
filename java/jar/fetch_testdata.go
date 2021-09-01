// +build tools

// Fetch is the script used to populate the stuff in testdir. This extracts a
// Cassandra distribution to do so, so unfortunately the URL hard-coded here
// needs to be kept in sync with the one in the actual test.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const (
	url = `https://archive.apache.org/dist/cassandra/4.0.0/apache-cassandra-4.0.0-bin.tar.gz`
)

func main() {
	log.Println("fetching", url)
	res, err := http.Get(url)
	if !errors.Is(err, nil) {
		log.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Fatalf("unexpected HTTP status: %v", res.Status)
	}
	if err := os.MkdirAll("testdata/manifest", 0755); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll("testdata/properties", 0755); err != nil {
		log.Fatal(err)
	}

	gz, err := gzip.NewReader(res.Body)
	if !errors.Is(err, nil) {
		log.Fatal(err)
	}
	defer gz.Close()
	t := tar.NewReader(gz)

	var h *tar.Header
	var buf bytes.Buffer
	for h, err = t.Next(); err == nil; h, err = t.Next() {
		if filepath.Ext(h.Name) != ".jar" {
			continue
		}
		buf.Grow(int(h.Size))
		if _, err := buf.ReadFrom(t); err != nil {
			log.Fatal(err)
		}
		rd := bytes.NewReader(buf.Bytes())
		if err := extractManifest("testdata/manifest", rd, h); err != nil {
			log.Fatal(err)
		}
		if err := extractProperties("testdata/properties", rd, h); err != nil {
			log.Fatal(err)
		}
		buf.Reset()
	}
	if !errors.Is(err, io.EOF) {
		log.Fatal(err)
	}
}

func extractManifest(prefix string, rd *bytes.Reader, h *tar.Header) error {
	const manifest = "META-INF/MANIFEST.MF"

	z, err := zip.NewReader(rd, rd.Size())
	if err != nil {
		return err
	}
	f, err := z.Open(manifest)
	if err != nil {
		// ???
		log.Printf("%s: no manifest", h.Name)
		return nil
	}
	defer f.Close()

	outname := filepath.Join(prefix, filepath.Base(h.Name))
	o, err := os.Create(outname)
	if err != nil {
		return err
	}
	defer o.Close()
	log.Printf("%s: extracting %q to %q", h.Name, manifest, o.Name())
	if _, err := io.Copy(o, f); err != nil {
		return err
	}
	return nil
}

func extractProperties(prefix string, rd *bytes.Reader, h *tar.Header) error {
	z, err := zip.NewReader(rd, rd.Size())
	if err != nil {
		return err
	}
	found := false
	for _, f := range z.File {
		if filepath.Base(f.Name) != "pom.properties" {
			continue
		}
		rd, err := f.Open()
		if err != nil {
			return err
		}
		defer rd.Close()
		outname := filepath.Join(prefix, filepath.Base(h.Name))
		o, err := os.Create(outname)
		if err != nil {
			return err
		}
		defer o.Close()
		log.Printf("%s: extracting %q to %q", h.Name, f.Name, o.Name())
		if _, err := io.Copy(o, rd); err != nil {
			return err
		}
		found = true
		// It's bad form to let these defers pile up, but this is just a script.
	}
	if !found {
		log.Printf("%s: no properties", h.Name)
	}
	return nil
}
