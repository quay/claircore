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

// ErrUnPurlable is returned when a PURL generator is not registered for a detector.
type ErrUnPurlable struct{ DetectorName string }

// Error returns the error message.
func (e ErrUnPurlable) Error() string {
	return fmt.Sprintf("no PURL generator registered for scanner %q", e.DetectorName)
}

// NewErrUnPurlable creates a new ErrUnPurlable.
func NewErrUnPurlable(detectorName string) ErrUnPurlable {
	return ErrUnPurlable{DetectorName: detectorName}
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
type GenerateFunc func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)

// ParseFunc produces IndexRecords for a given PackageURL.
type ParseFunc func(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error)

// Registry is a thread-safe registry of PURL generators and parsers.
type Registry struct {
	genRegistry       map[string]GenerateFunc
	parseRegistry     map[string]ParseFunc
	transformRegistry map[string][]TransformerFunc
	mu                sync.RWMutex
}

// NewRegistry creates a new PURLRegistry.
func NewRegistry() *Registry {
	return &Registry{
		genRegistry:       make(map[string]GenerateFunc),
		parseRegistry:     make(map[string]ParseFunc),
		transformRegistry: make(map[string][]TransformerFunc),
		mu:                sync.RWMutex{},
	}
}

// Generate finds a registered generator by the package's [claircore.Detector.Name]
// and returns the generated PackageURL.
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

// Parse finds a registered parser by the PURL's namespace and type and returns
// IndexRecords.
func (r *Registry) Parse(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	if purl.Namespace == "" {
		purl.Namespace = NoneNamespace
	}

	r.mu.RLock()
	transformFuncs, ok := r.transformRegistry[createPurlKey(purl.Type, purl.Namespace)]
	r.mu.RUnlock()
	// Unlocked during transform functions to avoid locking the registry
	// while external code is executing.
	if ok {
		for _, tf := range transformFuncs {
			err := tf(ctx, &purl)
			if err != nil {
				return nil, fmt.Errorf("purl transform error: %w", err)
			}
		}
	}
	r.mu.RLock()
	f, ok := r.parseRegistry[createPurlKey(purl.Type, purl.Namespace)]
	r.mu.RUnlock()
	if !ok {
		return nil, NewErrUnknownPurl(purl)
	}
	return f(ctx, purl)
}

// RegisterDetector registers using an indexer.PackageScanner (for its Name).
func (r *Registry) RegisterDetector(s indexer.PackageScanner, GenFn GenerateFunc) {
	r.mu.Lock()
	r.genRegistry[s.Name()] = GenFn
	r.mu.Unlock()
}

// TransformerFunc transforms a PackageURL before it is parsed.
type TransformerFunc func(ctx context.Context, purl *packageurl.PackageURL) error

// RegisterPurlType registers using a purl type. Transform functions are applied in
// registration order to the PackageURL before it is parsed.
func (r *Registry) RegisterPurlType(purlType string, purlNamespace string, ParseFn ParseFunc, transformFuncs ...TransformerFunc) {
	r.mu.Lock()
	r.parseRegistry[createPurlKey(purlType, purlNamespace)] = ParseFn
	r.transformRegistry[createPurlKey(purlType, purlNamespace)] = transformFuncs
	r.mu.Unlock()
}

func createPurlKey(purlType string, purlNamespace string) string {
	return purlType + "/" + purlNamespace
}
