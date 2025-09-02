package purl

import (
	"context"
	"fmt"
	"sync"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// GenerateFunc produces a PackageURL for a given IndexRecord.
// Implementations should be deterministic and side-effect free.
type GenerateFunc func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)

// ParseFunc produces an IndexRecord for a given PackageURL.
// Implementations should be deterministic and side-effect free.
type ParseFunc func(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error)

var (
	mu            sync.RWMutex
	genRegistry   = map[string]GenerateFunc{}
	parseRegistry = map[string]ParseFunc{}
)

// RegisterScanner registers using an indexer.PackageScanner (for its Name()).
func RegisterScanner(s indexer.PackageScanner, GenFn GenerateFunc) {
	mu.Lock()
	genRegistry[s.Name()] = GenFn
	mu.Unlock()
}

func RegisterParse(purlType string, ParseFn ParseFunc) {
	mu.Lock()
	parseRegistry[purlType] = ParseFn
	mu.Unlock()
}

// Generate finds a registered generator by the record's scanner name and
// returns the generated PackageURL.
func Generate(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	mu.RLock()
	f, ok := genRegistry[ir.Package.ScannerName]
	mu.RUnlock()
	if !ok {
		return packageurl.PackageURL{}, fmt.Errorf("no PURL generator registered for scanner %q", ir.Package.ScannerName)
	}
	return f(ctx, ir)
}

// Parse finds a registered generator by the record's scanner name and
// returns the generated PackageURL.
func Parse(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error) {
	mu.RLock()
	f, ok := parseRegistry[purl.Type]
	mu.RUnlock()
	if !ok {
		return &claircore.IndexRecord{}, fmt.Errorf("no PURL generator registered for purl type %q", purl.Type)
	}
	return f(ctx, purl)
}
