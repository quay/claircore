package purl

import (
	"context"
	"fmt"
	"sync"
	"unique"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ Converter = (*Registry)(nil)

const (
	// NoneNamespace is a placeholder namespace for PURLs that are not associated with
	// a specific namespace (optional according to the PURL spec), this is a canonical
	// value that can be used with [Registry.RegisterPurlType] to register a PURL type
	// without a namespace.
	NoneNamespace = "none"
)

// Converter is an interface that provides methods for generating and parsing PURLs.
type Converter interface {
	Generate(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)
	Parse(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error)
}

// ErrUnknownDetector is returned when a PURL generator is not registered for a detector.
type ErrUnknownDetector struct{ DetectorName string }

// Error returns the error message.
func (e ErrUnknownDetector) Error() string {
	return fmt.Sprintf("no PURL generator registered for detector %q", e.DetectorName)
}

// NewErrUnknownDetector creates a new ErrUnknownDetector.
func newErrUnknownDetector(detectorName string) ErrUnknownDetector {
	return ErrUnknownDetector{DetectorName: detectorName}
}

// ErrUnhandledPurl is returned when a PURL parser is not registered for a PURL type.
type ErrUnhandledPurl struct {
	Type      string
	Namespace string
}

// Error returns the error message.
func (e ErrUnhandledPurl) Error() string {
	return fmt.Sprintf("no PURL parser registered for type %q and namespace %q", e.Type, e.Namespace)
}

// NewErrUnhandledPurl creates a new ErrUnhandledPurl.
func newErrUnhandledPurl(purl packageurl.PackageURL) ErrUnhandledPurl {
	return ErrUnhandledPurl{Type: purl.Type, Namespace: purl.Namespace}
}

// GenerateFunc produces a PackageURL for a given IndexRecord.
type GenerateFunc func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error)

// ParseFunc produces IndexRecords for a given PackageURL.
type ParseFunc func(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error)

// Registry is a thread-safe registry of PURL generators and parsers.
type Registry struct {
	genRegistry   map[unique.Handle[string]]GenerateFunc
	parseRegistry map[unique.Handle[string]]parseTransform
	mu            sync.RWMutex
}

// NewRegistry creates a new PURLRegistry.
func NewRegistry() *Registry {
	return &Registry{
		genRegistry:   make(map[unique.Handle[string]]GenerateFunc),
		parseRegistry: make(map[unique.Handle[string]]parseTransform),
		mu:            sync.RWMutex{},
	}
}

type parseTransform struct {
	ParseFunc      ParseFunc
	TransformFuncs []TransformerFunc
}

// Generate finds a registered generator by the package's [claircore.Detector.Name]
// and returns the generated PackageURL.
func (r *Registry) Generate(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	if ir.Package == nil || ir.Package.Detector == nil || ir.Package.Detector.Name == "" {
		return packageurl.PackageURL{}, newErrUnknownDetector("unknown")
	}
	r.mu.RLock()
	f, ok := r.genRegistry[unique.Make(ir.Package.Detector.Name)]
	r.mu.RUnlock()
	if !ok {
		return packageurl.PackageURL{}, newErrUnknownDetector(ir.Package.Detector.Name)
	}
	return f(ctx, ir)
}

// Parse finds a registered parser and transform functions by the PURL's namespace and type.
// It then runs all transform functions and returns the parsed IndexRecords.
func (r *Registry) Parse(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	if purl.Namespace == "" {
		purl.Namespace = NoneNamespace
	}

	r.mu.RLock()
	pt, ok := r.parseRegistry[createPurlKey(purl.Type, purl.Namespace)]
	r.mu.RUnlock()
	if ok {
		for _, tf := range pt.TransformFuncs {
			err := tf(ctx, &purl)
			if err != nil {
				return nil, fmt.Errorf("purl transform error: %w", err)
			}
		}
	}
	if !ok {
		return nil, newErrUnhandledPurl(purl)
	}

	return pt.ParseFunc(ctx, purl)
}

// RegisterDetector registers using an [indexer.PackageScanner] (for its Name).
func (r *Registry) RegisterDetector(s indexer.PackageScanner, GenFn GenerateFunc) {
	detectorName := unique.Make(s.Name())
	r.mu.Lock()
	if _, ok := r.genRegistry[detectorName]; ok {
		panic(fmt.Sprintf("purl generator already registered for detector %q", s.Name()))
	}
	r.genRegistry[detectorName] = GenFn
	r.mu.Unlock()
}

// TransformerFunc transforms a PackageURL before it is parsed. Transform functions should
// take care to not overwrite existing qualifiers. If the Namespace or Type is modified, it
// will not affect the parsing of the PURL.If that is desired behaviour a new PURL Type and
// Namespace should be registered.
type TransformerFunc func(ctx context.Context, purl *packageurl.PackageURL) error

// RegisterPurlType registers using a purl type. Transform functions are applied in
// registration order to the PackageURL before it is parsed.
func (r *Registry) RegisterPurlType(purlType string, purlNamespace string, ParseFn ParseFunc, transformFuncs ...TransformerFunc) {
	r.mu.Lock()
	r.parseRegistry[createPurlKey(purlType, purlNamespace)] = parseTransform{ParseFunc: ParseFn, TransformFuncs: transformFuncs}
	r.mu.Unlock()
}

func createPurlKey(purlType string, purlNamespace string) unique.Handle[string] {
	return unique.Make(purlType + "/" + purlNamespace)
}
