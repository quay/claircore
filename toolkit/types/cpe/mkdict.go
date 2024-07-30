//go:build ignore

// Mkdict is a script to generate the TestDictionary harness from the official
// CPE Dictionary.
package main

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

const dictURL = `https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz`

func main() {
	var code int
	defer func() {
		if code != 0 {
			os.Exit(code)
		}
	}()
	outfile := flag.String("o", "testdata/dictionary.list.gz", "output file")
	flag.Parse()
	ctx := context.Background()

	out, err := os.Create(*outfile)
	if err != nil {
		slog.Error("unable to open out file", "error", err)
		code = 1
		return
	}
	defer out.Close()

	if err := Main(ctx, out); err != nil {
		slog.Error("error processing CPE dictionary", "error", err)
		code = 1
		return
	}
}

func Main(ctx context.Context, out *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dictURL, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("unexpected response: %s", res.Status)
	}
	inGz, err := gzip.NewReader(res.Body)
	if err != nil {
		return err
	}

	outGz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer outGz.Close()

	// This is a brittle loop that assumes the two versions of a bound CPE will
	// be paired. This should be true of the dictionary if it's adhering to the
	// schema.
	//
	// Doing it this way is significantly faster due to eliminating a bunch of
	// book-keeping allocations.

	dec := xml.NewDecoder(inGz)
	for {
		tok, err := dec.RawToken()
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return nil
		default:
			return err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			switch tok.Name.Local {
			case "cpe-item":
				io.WriteString(outGz, tok.Attr[0].Value)
				outGz.Write([]byte{'\t'})
			case "cpe23-item":
				io.WriteString(outGz, tok.Attr[0].Value)
				outGz.Write([]byte{'\n'})
			}
		}
	}
}
