package fixturescript

import (
	"errors"
	"io"
	"strconv"

	"github.com/quay/claircore"
)

// TODO(hank) Should this import `claircore`? Might be cycle concerns.

// CreateIndexReport ...
//
// Has the following commands:
//
//   - AddManifest (sets manifest digest, only allowed once)
//   - AddLayer (sets current layer digest)
//   - AddDistribution (sets current distribution)
//   - ClearDistribution (clears current distribution)
//   - PushRepository (pushes a repository onto the repository stack)
//   - PopRepository (pops a repository off the repository stack)
//   - AddPackage (emits a package using the current Distribution and repository stack)
func CreateIndexReport(name string, r io.Reader) (*claircore.IndexReport, error) {
	f := indexReportFixure{
		IndexReport: &claircore.IndexReport{
			Packages:      make(map[string]*claircore.Package),
			Distributions: make(map[string]*claircore.Distribution),
			Repositories:  make(map[string]*claircore.Repository),
			Environments:  make(map[string][]*claircore.Environment),
		},
	}
	pc := indexReportCtx{}
	return Parse(&f, &pc, name, r)
}

type indexReportFixure struct {
	IndexReport *claircore.IndexReport
}

type indexReportCtx struct {
	CurLayer         claircore.Digest
	CurDistribution  *claircore.Distribution
	CurSource        *claircore.Package
	CurPackageDB     string
	CurRepositoryIDs []string

	ManifestSet bool
	LayerSet    bool
}

func (f *indexReportFixure) Value() *claircore.IndexReport {
	return f.IndexReport
}

func (f *indexReportFixure) commonChecks(pc *indexReportCtx, args []string) error {
	switch {
	case len(args) == 0:
		return errors.New("bad number of arguments: want 1 or more")
	case !pc.ManifestSet:
		return errors.New("bad command: no Manifest created")
	case !pc.LayerSet:
		return errors.New("bad command: no Layer created")
	}
	return nil
}

func (f *indexReportFixure) AddManifest(pc *indexReportCtx, args []string) (err error) {
	if len(args) != 1 {
		return errors.New("bad number of arguments: want exactly 1")
	}
	if pc.ManifestSet {
		return errors.New("bad command: Manifest already created")
	}
	f.IndexReport.Hash, err = claircore.ParseDigest(args[0])
	if err != nil {
		return err
	}
	pc.ManifestSet = true
	return nil
}

func (f *indexReportFixure) AddLayer(pc *indexReportCtx, args []string) (err error) {
	if len(args) != 1 {
		return errors.New("bad number of arguments: want exactly 1")
	}
	if !pc.ManifestSet {
		return errors.New("bad command: no Manifest created")
	}
	pc.CurLayer, err = claircore.ParseDigest(args[0])
	return err
}

func (f *indexReportFixure) AddDistribution(pc *indexReportCtx, args []string) error {
	f.commonChecks(pc, args)
	d := claircore.Distribution{}
	if err := AssignToStruct(&d, args); err != nil {
		return err
	}
	pc.CurDistribution = &d
	return nil
}

func (f *indexReportFixure) ClearDistribution(pc *indexReportCtx, args []string) error {
	if len(args) == 0 {
		return errors.New("bad number of arguments: want 0")
	}
	pc.CurDistribution = nil
	return nil
}

func (f *indexReportFixure) PushRepository(pc *indexReportCtx, args []string) error {
	f.commonChecks(pc, args)
	r := claircore.Repository{}
	if err := AssignToStruct(&r, args); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = strconv.FormatInt(int64(len(f.IndexReport.Repositories)), 10)
	}
	f.IndexReport.Repositories[r.ID] = &r
	pc.CurRepositoryIDs = append(pc.CurRepositoryIDs, r.ID)
	return nil
}

func (f *indexReportFixure) PopRepository(pc *indexReportCtx, args []string) error {
	if len(args) != 0 {
		return errors.New("bad number of arguments: want 0")
	}
	last := len(pc.CurRepositoryIDs) - 1
	pc.CurRepositoryIDs = pc.CurRepositoryIDs[:last:last] // Forces a unique slice when down-sizing.
	return nil
}

func (f *indexReportFixure) AddPackage(pc *indexReportCtx, args []string) error {
	f.commonChecks(pc, args)
	p := claircore.Package{}
	if err := AssignToStruct(&p, args); err != nil {
		return err
	}
	if p.ID == "" {
		p.ID = strconv.FormatInt(int64(len(f.IndexReport.Packages)), 10)
	}
	p.Source = pc.CurSource
	f.IndexReport.Packages[p.ID] = &p
	env := claircore.Environment{
		PackageDB:     p.PackageDB,
		IntroducedIn:  pc.CurLayer,
		RepositoryIDs: pc.CurRepositoryIDs,
	}
	if pc.CurDistribution != nil {
		env.DistributionID = pc.CurDistribution.ID
	}
	f.IndexReport.Environments[p.ID] = []*claircore.Environment{&env}
	return nil
}
