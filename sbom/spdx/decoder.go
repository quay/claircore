package spdx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/package-url/packageurl-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/quay/claircore"
	"github.com/quay/claircore/purl"
	"github.com/quay/claircore/sbom"
)

// DecoderOption is a type for configuring a Decoder.
type DecoderOption func(*Decoder)

// Decoder defines an SPDX decoder that converts SPDX documents to [claircore.IndexReport].
type Decoder struct {
	// The data format to decode.
	Format Format
	// The PURL converter to use for parsing PURLs into IndexRecords.
	PURLConverter purl.Converter
}

var _ sbom.Decoder = (*Decoder)(nil)

// NewDefaultDecoder creates a Decoder with default values and sets optional
// fields based on the provided options.
func NewDefaultDecoder(options ...DecoderOption) *Decoder {
	d := &Decoder{
		Format: FormatJSON,
	}

	for _, opt := range options {
		opt(d)
	}

	return d
}

// WithDecoderFormat sets the format for decoding.
func WithDecoderFormat(f Format) DecoderOption {
	return func(d *Decoder) {
		d.Format = f
	}
}

// WithDecoderPURLConverter sets the PURL converter registry for parsing PURLs.
func WithDecoderPURLConverter(registry purl.Converter) DecoderOption {
	return func(d *Decoder) {
		d.PURLConverter = registry
	}
}

// Decode decodes an SPDX document from r and returns a [claircore.IndexReport].
//
// Known limitations:
//   - Only package indexing via PURL ExternalRefs is supported.
func (d *Decoder) Decode(ctx context.Context, r io.Reader) (*claircore.IndexReport, error) {
	var doc *v2_3.Document
	var err error

	switch d.Format {
	case FormatJSON:
		doc, err = spdxjson.Read(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read SPDX JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", d.Format)
	}

	return d.parseDocument(ctx, doc)
}

func (d *Decoder) parseDocument(ctx context.Context, doc *v2_3.Document) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{
		State:         "IndexFinished",
		Success:       true,
		Packages:      make(map[string]*claircore.Package),
		Distributions: make(map[string]*claircore.Distribution),
		Repositories:  make(map[string]*claircore.Repository),
		Environments:  make(map[string][]*claircore.Environment),
	}

	if d.PURLConverter == nil {
		slog.WarnContext(ctx, "no PURL converter configured, skipping PURL parsing")
		return ir, nil
	}

	// These will be used for their respective ids.
	pkgCounter := 1
	distCounter := 1
	repoCounter := 1

	for _, pkg := range doc.Packages {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		for _, ref := range pkg.PackageExternalReferences {
			// TODO(blugo): Consider supporting CPE parsing
			if ref.RefType != "purl" {
				continue
			}

			// Parse the PURL string to a proper PURL that the converter can use.
			pu, err := packageurl.FromString(ref.Locator)
			if err != nil {
				slog.WarnContext(ctx, "failed to parse PURL string to PURL",
					"purl", ref.Locator,
					"reason", err)
				continue
			}

			records, err := d.PURLConverter.Parse(ctx, pu)
			if err != nil {
				var unhandled purl.ErrUnhandledPurl
				if errors.As(err, &unhandled) {
					slog.WarnContext(ctx, "unregistered PURL type",
						"purl", ref.Locator,
						"type", unhandled.Type,
						"namespace", unhandled.Namespace)
				} else {
					slog.WarnContext(ctx, "failed to parse PURL to IndexRecords",
						"purl", ref.Locator,
						"reason", err)
				}
				continue
			}

			// Add each IndexRecord to the report.
			for _, record := range records {
				if record == nil || record.Package == nil {
					continue
				}

				// Add the package ID if we haven't recorded it yet.
				if record.Package.ID == "" {
					record.Package.ID = strconv.Itoa(pkgCounter)
					pkgCounter++
				}

				// Add the package if not already present
				pkgID := record.Package.ID
				if _, exists := ir.Packages[pkgID]; !exists {
					ir.Packages[pkgID] = record.Package
				}

				env := &claircore.Environment{}

				// Handle distribution
				if record.Distribution != nil {
					if record.Distribution.ID == "" {
						record.Distribution.ID = strconv.Itoa(distCounter)
						distCounter++
					}
					distID := record.Distribution.ID
					if _, exists := ir.Distributions[distID]; !exists {
						ir.Distributions[distID] = record.Distribution
					}
					env.DistributionID = distID
				}

				// Handle repository
				if record.Repository != nil {
					if record.Repository.ID == "" {
						record.Repository.ID = strconv.Itoa(repoCounter)
						repoCounter++
					}
					repoID := record.Repository.ID
					if _, exists := ir.Repositories[repoID]; !exists {
						ir.Repositories[repoID] = record.Repository
					}
					env.RepositoryIDs = append(env.RepositoryIDs, repoID)
				}

				ir.Environments[pkgID] = append(ir.Environments[pkgID], env)
			}
		}
	}

	return ir, nil
}
