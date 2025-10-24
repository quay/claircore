package purl

import (
	"context"
	"fmt"
	"sync"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	NoneNamespace = "none"
)

// PURLRegistry is an interface that provides methods for generating and parsing PURLs.
type PURLRegistry interface {
	Generate(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)
	Parse(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error)
}

// ErrUnPurlable is returned when a PURL generator is not registered for a scanner.
type ErrUnPurlable struct{ ScannerName string }

// Error returns the error message.
func (e ErrUnPurlable) Error() string {
	return fmt.Sprintf("no PURL generator registered for scanner %q", e.ScannerName)
}

// NewErrUnPurlable creates a new ErrUnPurlable.
func NewErrUnPurlable(scannerName string) ErrUnPurlable {
	return ErrUnPurlable{ScannerName: scannerName}
}

// ErrUnknownPurl is returned when a PURL parser is not registered for a PURL type.
type ErrUnknownPurl struct {
	Type      string
	Namespace string
}

// Error returns the error message.
func (e ErrUnknownPurl) Error() string {
	return fmt.Sprintf("no PURL parser registered for type %q and namespace %q", e.Type, e.Namespace)
}

// NewErrUnknownPurlType creates a new ErrUnknownPurl.
func NewErrUnknownPurl(purl packageurl.PackageURL) ErrUnknownPurl {
	return ErrUnknownPurl{Type: purl.Type, Namespace: purl.Namespace}
}

// GenerateFunc produces a PackageURL for a given IndexRecord.
// Implementations should be deterministic and side-effect free.
type GenerateFunc func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)

// ParseFunc produces an IndexRecord for a given PackageURL.
// Implementations should be deterministic and side-effect free.
type ParseFunc func(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error)

// Registry is a thread-safe registry of PURL generators and parsers.
type Registry struct {
	genRegistry   map[string]GenerateFunc
	parseRegistry map[string]ParseFunc
	mu            sync.RWMutex
}

// NewRegistry creates a new PURLRegistry.
func NewRegistry() *Registry {
	return &Registry{
		genRegistry:   make(map[string]GenerateFunc),
		parseRegistry: make(map[string]ParseFunc),
		mu:            sync.RWMutex{},
	}
}

// Generate finds a registered generator by the record's scanner name and
// returns the generated PackageURL.
func (r *Registry) Generate(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	if ir.Package == nil || ir.Package.Detector == nil || ir.Package.Detector.Name == "" {
		return packageurl.PackageURL{}, NewErrUnPurlable("unknown")
	}
	r.mu.RLock()
	f, ok := r.genRegistry[ir.Package.Detector.Name]
	r.mu.RUnlock()
	if !ok {
		return packageurl.PackageURL{}, NewErrUnPurlable(ir.Package.Detector.Name)
	}
	return f(ctx, ir)
}

// Parse finds a registered parser by the record's scanner name and
// returns the generated PackageURL.
func (r *Registry) Parse(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error) {
	r.mu.RLock()
	if purl.Namespace == "" {
		purl.Namespace = NoneNamespace
	}
	f, ok := r.parseRegistry[createPurlKey(purl.Type, purl.Namespace)]
	r.mu.RUnlock()
	if !ok {
		return nil, NewErrUnknownPurl(purl)
	}
	return f(ctx, purl)
}

// RegisterScanner registers using an indexer.PackageScanner (for its Name).
func (r *Registry) RegisterScanner(s indexer.PackageScanner, GenFn GenerateFunc) {
	r.mu.Lock()
	r.genRegistry[s.Name()] = GenFn
	r.mu.Unlock()
}

// RegisterPurlType registers using a purl type.
func (r *Registry) RegisterPurlType(purlType string, purlNamespace string, ParseFn ParseFunc) {
	r.mu.Lock()
	r.parseRegistry[createPurlKey(purlType, purlNamespace)] = ParseFn
	r.mu.Unlock()
}

func createPurlKey(purlType string, purlNamespace string) string {
	return purlType + "/" + purlNamespace
}
